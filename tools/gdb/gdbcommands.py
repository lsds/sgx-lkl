# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import sys

# Execute given command.
def gdb_execute(command):
    output = gdb.execute(command, from_tty=False, to_string=True)
    if output:
        print(output)
        gdb.execute("refresh")

class LKLFinishBreakpoint(gdb.FinishBreakpoint):
    """
        Replacement for FinishBreakpoint that works with the
        LKL thread scheduler.
    """
    def __init__(self, frame):
        super(LKLFinishBreakpoint, self).__init__(frame,
                                                  internal=True)
        # Set the breakpoint as having no specific thread so
        # that it is robust to LKL thread switching.
        self.thread = None
        # Don't display messages when hit.
        self.silent = True
        # Correct hit count
        self.correct_hit_count = 0

        # Even if the LThread is tranferred between different EThreads,
        # the stack frames and hence RSP will be preserved. Thus the
        # caller RSP acts as a good unique identifier for this
        # finish breakpoint.
        self.caller_rsp = frame.older().read_register('rsp')

        # For host/enclave transition boundary, this seems to be needed.
        self.caller_frame_id = str(frame.older())

    def stop(self):
        try:
            # Stop only if we have returned back to the caller.
            # If another thread hits this breakpoint, its caller RSP
            # will be different.
            frame = gdb.newest_frame()
            current_rsp = frame.read_register('rsp')
            current_frame_id = str(frame)
            if current_rsp == self.caller_rsp or \
               current_frame_id == self.caller_frame_id:
                #TODO: Better return value printing.
                print("Value returned is " + str(self.return_value))
                self.correct_hit_count = 1
                return True
        except:
            pass
        return False


class LKLFinish(gdb.Command):
    """
        A drop in replacement for GDB's 'finish' command that works
        with the LKL thread scheduler.
    """
    def __init__(self):
        # Override the 'finish' command. Change this to 'lkl-finish' if you
        # want to retain the original implementation.
        command = 'finish'
        print("Overriding 'finish' with LKL compatible 'lkl-finish'. "
              "finish will now work with LKL.")
        super(LKLFinish, self).__init__(command, gdb.COMMAND_USER)

    @staticmethod
    def do_finish(frame):
        # When function are inlined, but have debud info,
        # both the current and older frames have the same pc.
        # Skip over all such frames and set the breakpoint.
        while frame.pc() == frame.older().pc():
            frame = frame.older()

        # TODO: We also need to skip this sequence too.
        # Document this.
        caller = frame.older()
        while caller.older() and caller.older().pc() == caller.pc():
            frame = caller
            caller = frame.older()

        # After having figured out correct frame, set LKL compatible
        # breakpoint.
        bp = LKLFinishBreakpoint(frame)

        # Continue execution
        gdb_execute('continue')

        # Check if we stopped due to finish breakpoint being hit
        # or due to some other reason
        hit = bp.correct_hit_count > 0

        if bp.is_valid():
            bp.delete()
        return hit

    def print_advice(self):
        print("lkl-finish could not determine what to do. "
              "It is recommended that you manually place a breakpoint "
              "and continue at this time.")

    def invoke(self, arg, from_tty):
        try:
            # Fetch the current frame
            current_frame = gdb.newest_frame()
            if not current_frame:
                self.print_advice()
                return
            LKLFinish.do_finish(current_frame)
        except:
            _, ex, _ = sys.exc_info()
            print(ex)
            self.print_advice()


class LKLBreakpoint(gdb.Breakpoint):
    """
        Thread-specific breakpoint that works LKL thread scheduler.
    """
    def __init__(self, where, frame):
        super(LKLBreakpoint, self).__init__(where,
                                            internal=True)
        # Set the breakpoint as having no specific thread so
        # that it is robust to LKL context switching.
        self.thread = None
        # Don't display messages when hit.
        self.silent = True
        # Correct hit count
        self.correct_hit_count = 0

        # Even if the LThread is tranferred between different EThreads,
        # the stack frames and hence RSP will be preserved. Thus the
        # caller RSP acts as a good unique identifier for this
        # finish breakpoint.
        self.frame_id = str(frame)

        # Use the caller as a secondary id
        caller_frame = frame.older()
        self.caller_frame_id = str(caller_frame) if caller_frame else None

    def stop(self):
        try:
            # Stop only if we have returned back to the caller.
            # If another thread hits this breakpoint, its caller RSP
            # will be different.
            frame = gdb.newest_frame()
            frame_id = str(frame)
            caller_frame = frame.older()
            caller_frame_id = str(caller_frame) if caller_frame else None
            if frame_id == self.frame_id \
               or caller_frame_id == self.caller_frame_id:
                self.correct_hit_count = 1
                return True
        except:
            pass
        return False

class LKLNext(gdb.Command):
    """
        A drop in replacement for GDB's 'next' command that works
        with the LKL thread scheduler.
    """
    def __init__(self):
        # Override the 'next' command. Change this to 'lkl-next' if you
        # want to retain the original implementation.
        command = 'next'
        print("Overriding 'next' with LKL compatible 'lkl-next'. "
              "next and n will now work with LKL.")
        super(LKLNext, self).__init__(command, gdb.COMMAND_USER)


    def current_frame(self):
        try:
            frame = gdb.newest_frame()
            return frame
        except:
            print("lkl-next could not determine current frame.")
            return None

    def current_sal(self):
        try:
            # In some cases, the object returned by frame.find_sal()
            # has empty pc and last. Whereas the object returned by
            # gdb.find_pc_line(frame.pc()) has accurate pc and last.
            # Weird.
            # E.g: arch/lkl/kernel/syscalls.c:122:
            #      ret = run_syscall(no, parames)
            # Reproduction:
            #   $make run-hw-gdb  # helloworld sample
            #   (gdb) b syscalls.c:120
            #   (gdb) n
            #   (gdb) python print(gdb.newest_frame().find_sal().pc)
            #   0                 <-------- incorrect
            #   (gdb) python print(gdb.find_pc_line(gdb.newest_frame().pc()).pc)
            #   140733194943702   <-------- correct
            # The above issue happens on GDB 8.3, but does not happen on
            # GDB 8.1.
            frame = self.current_frame()
            sal = gdb.find_pc_line(frame.pc())
            return sal
        except:
            return None

    def print_advice(self):
        print("lkl-next could not determine what to do. "
              "It is recommended that you manually place a breakpoint "
              "and continue at this time.")

    def intelligent_step(self, frame, sal):
        # Disassemble instructions at current pc.
        asm = frame.architecture().disassemble(start_pc=frame.pc(),
                                               end_pc=sal.last)

        # We want to put a breakpoint and then 'continue' execution
        # till that breakpoint. It is safe to 'continue' execution
        # till we hit a branch or return instruction. Even calls are ok
        # since we will return from the call.
        # We don't know where branches will jump to; therefore we search
        # for jumps (all start with 'j') or ret instruction.
        bp_addr = None
        for a in asm[1:]:
            ins = a['asm']
            if ins.startswith('j') or ins.startswith('ret'):
                bp_addr = a['addr']
                break

        # gcc 8 and above generate endbr64 as the first instruction in
        # a function. An address breakpoint set immediately after it does
        # not work. It is better to do a step.
        # E.g: b lkl_poststart_net
        if len(asm) == 1 and asm[0]['asm'].startswith('endbr64'):
            return False

        # Check if the current source line has a jump or return.
        if bp_addr:
            # If yes, set breakpoint. Handle case where the first
            # instruction itself is a jump. In that case, we will
            # step.
            if bp_addr == frame.pc():
                return False
            bp = LKLBreakpoint('*' + hex(a['addr']), frame)
        else:
            # The source line does not have branches or returns.
            # Set breakpoint at beyond the last instruction.
            last_insn = asm[-1]
            location = last_insn['addr'] + last_insn['length']
            bp = LKLBreakpoint('*' + hex(location), frame)

        # Continue execution till the breakpoint. But we could
        # stop due to some other reason (another breakpoint or exception)
        # before our breakpoint is hit.
        interrupted = True
        if bp:
            gdb_execute("continue")
            if bp.is_valid():
                # If the breakpoint's hit count is zero, then we stopped
                # due to some other reason.
                interrupted = bp.correct_hit_count == 0
                bp.delete()
                return interrupted

        return interrupted

    def invoke(self, arg, from_tty):
        try:
            # Fetch the current frame
            start_frame = self.current_frame()
            if not start_frame:
                self.print_advice()
                return

            # Fetch the symbol and line. We will keep stepping until
            # the current line number changes
            start_sal = self.current_sal()
            if not start_sal:
                self.print_advice()
                return

            # Intelligently do the first step
            # In lines of code without branches, we will be done
            # after the intelligent step
            done = self.intelligent_step(start_frame, start_sal)

            # TODO: See if we can avoid stepping and use only
            # breakpoints and continue.
            while not done:
                 # Check if the current location has a frame
                cur_frame = self.current_frame()
                if not cur_frame:
                    gdb_execute('step')
                    continue

                # Check if the current location has line information.
                cur_sal = self.current_sal()
                if not cur_sal:
                    gdb_execute('step')
                    continue

                # If we are still in the starting line, step again.
                if cur_sal.line == start_sal.line:
                    gdb_execute('step')
                    continue

                # The line number is different.
                # Line number will change when
                # a) we step over a line
                # b) if we have returned from the curernt function
                # c) if we have stepped into another function.
                # There is nothing to be done for (a) and (b).
                # For (c), we need to return to the caller via
                # the equivalent of a finish command.
                if cur_frame.older() == start_frame:
                    finished = LKLFinish.do_finish(cur_frame)
                    if finished:
                        continue
                    else:
                        # Another breakpoint was hit, quit stepping
                        return
                else:
                    # We have stepped over a line or returned from the
                    # current function
                    break

        except:
            # Cannot reliably do a 'next'
            _, ex, _ = sys.exc_info()
            print(ex)
            self.print_advice()


class LKLNexti(gdb.Command):
    """
        A drop in replacement for GDB's 'nexti' command that works
        with the LKL thread scheduler.
    """
    def __init__(self):
        # Override the 'nexti' command. Change this to 'lkl-nexti' if you
        # want to retain the original implementation.
        command = 'nexti'
        print("Overriding 'nexti' with LKL compatible 'lkl-nexti'. "
              "nexti and ni will now work with LKL.")
        super(LKLNexti, self).__init__(command, gdb.COMMAND_USER)

    def print_advice(self):
        print("lkl-nexti could not determine what to do. "
              "It is recommended that you manually place a breakpoint "
              "and continue at this time.")

    def invoke(self, arg, from_tty):
        try:
            # Disassemble two instructions from current pc.
            frame = gdb.newest_frame()
            asm = frame.architecture().disassemble(start_pc=frame.pc(),
                                                   count=2)

            # Determine if the current instruction is a call.
            # If false, invoke stepi.
            curr_ins = asm[0]
            if curr_ins['asm'].find('call') == -1:
                gdb.execute('stepi')
                return

            # Special case: the very last instruction is a call. Invoke stepi.
            # Note that this should be a rare case.
            if len(asm) < 2:
                gdb.execute('stepi')
                return

            # If true, set a break point at the next instruction and continue.
            next_ins = asm[1]
            bp = LKLBreakpoint('*' + hex(next_ins['addr']), frame)
            if bp:
                gdb.execute("continue")
                if bp.is_valid():
                    bp.delete()
                    # Inovke the display to be consistent with normal behavior of ni.
                    gdb.execute("display")

        except:
            # Cannot reliably do a 'nexti'
            _, ex, _ = sys.exc_info()
            print(ex)
            self.print_advice()

def register():
    LKLFinish()
    LKLNext()
    LKLNexti()

if __name__ == '__main__':
    register()
