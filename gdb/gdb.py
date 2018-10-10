# To use, add source /path/to/gdb.py to your $HOME/.gdbinit file.

import atexit
import os
import re
import subprocess
import tempfile
import textwrap as tw

def add_symbol_file(filename, baseaddr):
    sections = []
    textaddr = '0'

    p = subprocess.Popen(["readelf", "-SW", filename], stdout=subprocess.PIPE)

    for line in p.stdout.readlines():
        line = line.decode("utf-8").strip()
        if not line.startswith('[') or line.startswith('[Nr]'):
            continue

        line = re.sub(r'\[ *(\d+)\]', '\\1', line)
        sec = dict(zip(['nr', 'name', 'type', 'addr'], line.split()))

        if sec['nr'] == '0':
            continue

        if sec['name'] == '.text':
            textaddr = sec['addr']
        elif int(sec['addr'], 16) != 0:
            sections.append(sec)

    cmd = "add-symbol-file %s 0x%08x" % (filename, int(textaddr, 16) + baseaddr)

    for s in sections:
        addr = int(s['addr'], 16)
        if s['name'] == '.text' or addr == 0:
            continue

        cmd += " -s %s 0x%x" % (s['name'], int(baseaddr + addr))

    gdb.execute(cmd)


class StarterExecBreakpoint(gdb.Breakpoint):
    STARTER_HAS_LOADED = '__gdb_hook_starter_ready'
    LIBC_LOCATION = os.path.dirname(os.path.realpath(__file__)) + '/../build/libsgxlkl.so'

    def __init__(self):
        super(StarterExecBreakpoint, self).__init__(self.STARTER_HAS_LOADED, internal=True)
        self.inited = False

    def stop(self):
        base_addr = gdb.parse_and_eval('conf->base')
        in_hw_mode = gdb.parse_and_eval('conf->mode == SGXLKL_HW_MODE')
        if in_hw_mode:
            gdb.write('Running on hardware... skipping simulation load.\n')
        else:
            gdb.write('Loading symbols for %s at base 0x%x...\n' % (
                self.LIBC_LOCATION, int(base_addr)))
            add_symbol_file(self.LIBC_LOCATION, int(base_addr))

        if not self.inited and gdb.lookup_global_symbol("__gdb_load_debug_symbols_alive"):
            gdb.write('Enabled loading in-enclave debug symbols\n')
            gdb.execute('set __gdb_load_debug_symbols_alive = 1')
            self.inited = True
            LoadLibraryBreakpoint()
            LoadLibraryFromFileBreakpoint()

        return False


class LoadLibraryBreakpoint(gdb.Breakpoint):
    LDSO_LOAD_LIBRARY = '__gdb_hook_load_debug_symbols'

    def __init__(self):
        super(LoadLibraryBreakpoint, self).__init__(self.LDSO_LOAD_LIBRARY, internal=True)

    def stop(self):
        # dump symbols out to disk
        uintptr_t = gdb.lookup_type('uintptr_t')
        ssize_t = gdb.lookup_type('ssize_t')

        mem_loc = int(gdb.parse_and_eval('symmem').cast(uintptr_t))
        mem_sz = int(gdb.parse_and_eval('symsz').cast(ssize_t))
        memvw = gdb.selected_inferior().read_memory(mem_loc, mem_sz)

        # work out where new library is loaded
        base_addr = int(gdb.parse_and_eval('dso->base').cast(uintptr_t))
        fn = None
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as f:
            f.write(memvw)
            fn = f.name

        gdb.write('Loading symbols at base 0x%x...\n' % (int(base_addr)))
        add_symbol_file(fn, int(base_addr))

        atexit.register(os.unlink, fn)
        return False


class LoadLibraryFromFileBreakpoint(gdb.Breakpoint):
    LDSO_LOAD_LIBRARY_FROM_FILE = '__gdb_hook_load_debug_symbols_from_file'

    def __init__(self):
        super(LoadLibraryFromFileBreakpoint, self).__init__(self.LDSO_LOAD_LIBRARY_FROM_FILE, internal=True)

    def stop(self):
        uintptr_t = gdb.lookup_type('uintptr_t')
        libpath = gdb.execute('printf "%s", libpath', to_string=True)
        base_addr = int(gdb.parse_and_eval('dso->base').cast(uintptr_t))

        gdb.write('Loading symbols at base 0x%x...\n' % (int(base_addr)))
        add_symbol_file(libpath, int(base_addr))

        return False


class LthreadBacktrace(gdb.Command):
    """
        Print backtrace for an lthread
        Param 1: Address of lthread
        Param 2: Backtrace depth (optional)
    """
    def __init__(self):
        super(LthreadBacktrace, self).__init__("lthread-bt", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if not argv:
            gdb.write('No lthread address provided. Usage: lthread-bt <addr> [<btdepth>]\n')
            gdb.flush()
            return False
        lt_addr = argv[0]
        if len(argv) > 1:
            btdepth = argv[1]
        else:
            btdepth = ""

        old_fp = gdb.execute('p/x $rbp', to_string=True).split('=')[1].strip()
        old_sp = gdb.execute('p/x $rsp', to_string=True).split('=')[1].strip()
        old_ip = gdb.execute('p/x $rip', to_string=True).split('=')[1].strip()

        gdb.execute('set $rbp = ((struct lthread *)%s)->ctx.ebp'%lt_addr)
        gdb.execute('set $rsp = ((struct lthread *)%s)->ctx.esp'%lt_addr)
        gdb.execute('set $rip = ((struct lthread *)%s)->ctx.eip'%lt_addr)

        gdb.execute('bt %s'%btdepth)

        # Restore registers
        gdb.execute('set $rbp = %s'%old_fp)
        gdb.execute('set $rsp = %s'%old_sp)
        gdb.execute('set $rip = %s'%old_ip)

        return False


class LthreadStats(gdb.Command):
    """
        Prints the number of lthreads in the futex, scheduler, and syscall queues.
    """
    def __init__(self):
        super(LthreadStats, self).__init__("lthread-stats", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if argv and len(argv) > 0:
            btdepth = argv[0]
        else:
            btdepth = ""

        schedq_lts = 0
        syscall_req_lts = 0
        syscall_ret_lts = 0
        fxq_lts = 0

        schedq_lts = self.count_queue_elements('__scheduler_queue')
        syscall_req_lts = self.count_queue_elements('__syscall_queue')
        syscall_ret_lts = self.count_queue_elements('__return_queue')

        fxq = gdb.execute('p/x futex_queues->slh_first', to_string=True).split('=')[1].strip()
        while(int(fxq, 16) != 0):
            fxq_lts = fxq_lts + 1;
            fxq = gdb.execute('p/x ((struct futex_q*)%s)->entries.sle_next'%fxq, to_string=True).split('=')[1].strip()

        waiting_total = schedq_lts + syscall_req_lts + syscall_ret_lts + fxq_lts

        gdb.write('Waiting lthreads:\n')
        gdb.write('  scheduler queue:       %s\n'%schedq_lts)
        gdb.write('  syscall request queue: %s\n'%syscall_req_lts)
        gdb.write('  syscall return queue:  %s\n'%syscall_ret_lts)
        gdb.write('  waiting for futex:     %s\n'%fxq_lts)
        gdb.write('  Total:                 %s\n'%waiting_total)
        gdb.flush()

        return False

    def count_queue_elements(self, queue):
        enqueue_pos = int(gdb.execute('p %s->enqueue_pos'%queue, to_string=True).split('=')[1].strip())
        dequeue_pos = int(gdb.execute('p %s->dequeue_pos'%queue, to_string=True).split('=')[1].strip())
        return enqueue_pos - dequeue_pos


class LogAllLts(gdb.Command):
    """
        Do a backtrace of all active lthreads.
        Param: Depth of backtrace (optional)
    """
    def __init__(self):
        super(LogAllLts, self).__init__("bt-lts", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if argv and len(argv) > 0:
            btdepth = argv[0]
        else:
            btdepth = ""

        ltq = gdb.execute('p/x __active_lthreads', to_string=True).split('=')[1].strip()

        no = 1
        while(int(ltq, 16) != 0):
            lt = gdb.execute('p/x ((struct lthread_queue*)%s)->lt'%ltq, to_string=True).split('=')[1].strip()
            lt_tid = gdb.execute('p/d ((struct lthread_queue*)%s)->lt->tid'%ltq, to_string=True).split('=')[1].strip()
            lt_name = gdb.execute('p/s ((struct lthread_queue*)%s)->lt->funcname'%ltq, to_string=True).split('=')[1].strip().split(',')[0]
            gdb.write('#%3d Lthread: TID: %3s, Addr: %s, Name: %s\n'%(no, lt_tid, lt, lt_name))
            gdb.execute('lthread-bt %s %s'%(lt, btdepth))
            gdb.write('\n')
            gdb.flush()

            ltq = gdb.execute('p/x ((struct lthread_queue*)%s)->next'%ltq, to_string=True).split('=')[1].strip()
            no = no + 1

        return False


class LogFxWaiters(gdb.Command):
    """
        Do a backtrace of all lthreads waiting on a futex
        Param: Depth of backtrace (optional)
    """
    def __init__(self):
        super(LogFxWaiters, self).__init__("bt-fxq", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if argv and len(argv) > 0:
            btdepth = argv[0]
        else:
            btdepth = ""

        fxq = gdb.execute('p/x futex_queues->slh_first', to_string=True).split('=')[1].strip()

        while(int(fxq, 16) != 0):
            ft_lt = gdb.execute('p/x ((struct futex_q*)%s)->futex_lt'%fxq, to_string=True).split('=')[1].strip()
            ft_key = gdb.execute('p ((struct futex_q*)%s)->futex_key'%fxq, to_string=True).split('=')[1].strip()
            ft_deadline = gdb.execute('p ((struct futex_q*)%s)->futex_deadline'%fxq, to_string=True).split('=')[1].strip()
            gdb.write('FX entry: key: %s, lt: %s, deadline: %s\n'%(ft_key, ft_lt, ft_deadline))
            gdb.execute('lthread-bt %s %s'%(ft_lt, btdepth))
            gdb.write('\n')
            gdb.flush()

            fxq = gdb.execute('p/x ((struct futex_q*)%s)->entries.sle_next'%fxq, to_string=True).split('=')[1].strip()

        return False


class LogSchedQueueTids(gdb.Command):
    """
        Print thread id of each lthread in scheduler queue.
    """
    def __init__(self):
        super(LogSchedQueueTids, self).__init__("schedq-tids", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):

        enqueue_pos = int(gdb.execute('p __scheduler_queue->enqueue_pos', to_string=True).split('=')[1].strip())
        dequeue_pos = int(gdb.execute('p __scheduler_queue->dequeue_pos', to_string=True).split('=')[1].strip())
        if (enqueue_pos < dequeue_pos): raise Exception("Logic error: %d < %d"%(enqueue_pos, dequeue_pos))

        buffer_mask = int(gdb.execute('p __scheduler_queue->buffer_mask', to_string=True).split('=')[1].strip())

        tids = []
        for i in range(dequeue_pos, enqueue_pos):
            gdb.write('p ((struct lthread*)__scheduler_queue->buffer[%d & %d].data)->tid\n'%(i, buffer_mask))
            tid = int(gdb.execute('p ((struct lthread*)__scheduler_queue->buffer[%d & %d].data)->tid'%(i, buffer_mask), to_string=True).split('=')[1].strip())
            tids.append(tid)

        gdb.write('\nScheduler queue lthreads:\n'+tw.fill(str(tids))+'\n')
        gdb.flush()


class LogSyscallBacktraces(gdb.Command):
    """
        Print backtraces for all lthreads waiting in the syscall queues.
        Param: Depth of backtrace (optional)
    """
    def __init__(self):
        super(LogSyscallBacktraces, self).__init__("bt-syscallqueues", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        if argv and len(argv) > 0:
            btdepth = argv[0]
        else:
            btdepth = ""

        gdb.write('Lthreads in system call request queue:\n')
        self.print_bts_for_queue('__syscall_queue', btdepth)
        gdb.write('\nLthreads in system call return queue:\n')
        self.print_bts_for_queue('__return_queue', btdepth)

        return False

    def print_bts_for_queue(self, queue, btdepth):
        enqueue_pos = int(gdb.execute('p %s->enqueue_pos'%queue, to_string=True).split('=')[1].strip())
        dequeue_pos = int(gdb.execute('p %s->dequeue_pos'%queue, to_string=True).split('=')[1].strip())
        if (enqueue_pos < dequeue_pos): raise Exception("Logic error: %d < %d"%(enqueue_pos, dequeue_pos))

        buffer_mask = int(gdb.execute('p %s->buffer_mask'%queue, to_string=True).split('=')[1].strip())

        for i in range(dequeue_pos, enqueue_pos):
            lt = gdb.execute('p/x slotlthreads[%s->buffer[%d & %d].data]'%(queue, i, buffer_mask), to_string=True).split('=')[1].strip()
            if(lt != '0x0'):
                tid = int(gdb.execute('p ((struct lthread*)%s)->tid'%lt, to_string=True).split('=')[1].strip())
                gdb.write('Lthread [tid=%d]\n'%tid)
                gdb.execute('lthread-bt %s %s'%(lt, btdepth))
                gdb.write('\n')
            else:
                gdb.write('Queue entry without associated lthread...\n')

        gdb.flush()


class LogSyscallTids(gdb.Command):
    """
        Print tids of lthreads in syscall and return queues.
    """
    def __init__(self):
        super(LogSyscallTids, self).__init__("syscall-tids", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        gdb.write('\nSlot tids:\n'+tw.fill(str(self.slot_tids())))
        gdb.write('\nSlot syscallnos:\n'+tw.fill(str(self.syscall_nos())))
        gdb.write('\nSyscall tids:\n'+tw.fill(str(self.queue_tids('syscall'))))
        gdb.write('\nReturn tids:\n'+tw.fill(str(self.queue_tids('return'))))
        gdb.flush()


    def slot_tids(self):
        maxsyscalls = int(gdb.execute('p maxsyscalls', to_string=True).split('=')[1].strip())
        slot_tids = {}
        for i in range(0, maxsyscalls):
            if int(gdb.execute('p (int)slotlthreads[%d]'%i, to_string=True).split('=')[1].strip()) != 0:
                tid = int(gdb.execute('p slotlthreads[%d]->tid'%i, to_string=True).split('=')[1].strip())
                slot_tids[i] = tid

        return slot_tids

    def queue_tids(self, queue):
        enqueue_pos = int(gdb.execute('p __%s_queue->enqueue_pos'%queue, to_string=True).split('=')[1].strip())
        dequeue_pos = int(gdb.execute('p __%s_queue->dequeue_pos'%queue, to_string=True).split('=')[1].strip())
        if (enqueue_pos < dequeue_pos): raise Exception("Logic error: %d < %d"%(enqueue_pos, dequeue_pos)) 

        buffer_mask = int(gdb.execute('p __%s_queue->buffer_mask'%queue, to_string=True).split('=')[1].strip())

        tids = []
        for i in range(dequeue_pos, enqueue_pos):
            slot = int(gdb.execute('p ((int)__%s_queue->buffer[%d & %d].data)'%(queue, i, buffer_mask), to_string=True).split('=')[1].strip())
            if int(gdb.execute('p (int)slotlthreads[%d]'%slot, to_string=True).split('=')[1].strip()) != 0:
                tid = int(gdb.execute('p slotlthreads[%d]->tid'%slot, to_string=True).split('=')[1].strip())
                tids.append(tid)
            else:
                gdb.write('\nNo lthread found for queue slot %d in slotlthreads\n'%slot)

        return tids

    def syscall_nos(self):
        maxsyscalls = int(gdb.execute('p maxsyscalls', to_string=True).split('=')[1].strip())
        slot_syscallnos = {}
        for i in range(0, maxsyscalls):
            if int(gdb.execute('p (int)slotlthreads[%d]'%i, to_string=True).split('=')[1].strip()) != 0:
                sno = int(gdb.execute('p S[%d].syscallno'%i, to_string=True).split('=')[1].strip())
                slot_syscallnos[i] = sno

        return slot_syscallnos

if __name__ == '__main__':
    StarterExecBreakpoint()
    LthreadBacktrace()
    LthreadStats()
    LogAllLts()
    LogFxWaiters()
    LogSchedQueueTids()
    LogSyscallBacktraces()
    LogSyscallTids()
