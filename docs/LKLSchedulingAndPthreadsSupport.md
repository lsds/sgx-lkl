# LKL Scheduling and Pthreads Support

## Pre-requisites
Please read [Threading.md](Threading.md) for a good overview of SGX-LKL threading concepts.

## Thread identities
A thread has 3 identities:
- Linux process context - `task_struct`
- LKL arch specific process context - [`thread_info`](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/include/asm/thread_info.h#L29)
- LKL host thread context, implemented in SGX-LKL by `lthread`s.

Not every lthread corresponds to a LKL thread. In conventional LKL usage, the Linux process contexts are allocated lazily on the first system call. In cloned threads, the Linux process context is allocated eagerly during thread creation.

In general once LKL knows about a lthread, there is a 1:1 mapping between these identities. Later we'll detail an exception to this in the [pthread_create](#pthread_create) section.

## LKL's CPU Lock: 
The LKL CPU lock allows a single thread to be running inside LKL.
The `lkl_cpu` structure defined in [`arch/lkl/kernel/cpu.c`](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/kernel/cpu.c) consists of a `lkl_mutex`, a `lkl_sem` and some status data like `owner`, `count` and `sleepers`.

The `lkl_mutex *lock` is used to ensure mutual exclusion while accessing/modifying the status data fields.
The CPU semaphore `lkl_sem *sem` allows threads to sleep if there is an `owner` already.
The `owner` of the lock is assigned and checked based on the lthread identity.

Threads entering LKL via `lkl_syscall` [try to acquire the lock](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/kernel/syscalls.c#L187) by calling `lkl_cpu_get`. Once the syscall is processed, the [lock is released](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/kernel/syscalls.c#L310) on the return path by a `lkl_cpu_put`.

The LKL scheduler [also transfers lock ownership during task switching](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/kernel/threads.c#L182) via `lkl_cpu_change_owner`.

## sched_sem: thread level semaphore LKL uses to control scheduling
From the LKL paper -
> To regain control of scheduling, the generic LKL architecture layer associates
> an environment-provided semaphore with each LKL thread.
>
> Immediately after creation, and before running any Linux code each LKL thread
> acquires its corresponding semaphore, and gets blocked as the semaphore's
> initial value is 0.
>
> When the Linux scheduler selects a new thread to run, it releases the semaphore
> of the new thread and immediately acquires its own semaphore.
>
> The new thread will start running and the old one stops.
>
> This token passing mechanism ensures that at any given time there is only one
> thread running and the scheduling order is dictated by the Linux scheduler.

O. Purdila, L. A. Grijincu and N. Tapus, "LKL: The Linux kernel library," 9th RoEduNet IEEE International Conference, Sibiu, 2010, pp. 328-333.

The environment-provided semaphore is the [`sched_sem`](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/include/asm/thread_info.h#L34) field in `thread_info`.

## thread_sched_jb(): setjmp/longjmp with LKL scheduler
[`thread_sched_jb`](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/include/asm/sched.h#L7) provides a mechanism to do non-local jumps between the current thread context and the scheduler. LKL uses a [host provided implementation](https://github.com/lsds/sgx-lkl/blob/0c95637ca94ca9a92680169fb8941ffc12e33c3f/src/lkl/jmp_buf.c) for the setjmp and longjmp operations.

Before calling the scheduler, a flag(TIF_SCHED_JB) is added to the task's flags. This helps identify this task later, in the architecture dependent task switching routine `__switch_to`.
Once the thread is in `__switch_to(prev, next)`, the CPU ownership is transferred to the next task (It is implied that `thread_sched_jb` was called with the CPU lock held). And then if the `TIF_SCHED_JB` flag is set, the thread long jumps back to `threads_sched_jb`. 
There are no instructions on the return path in `thread_sched_jb`, and the function ends.

Call graph covering invocation of `thread_sched_jb`, setting the jump buffer and the long jump back from the scheduler:
```
thread_sched_jb()
    - current.ti.flags = TIF_SCHED_JB
    - current.state = TASK_UNINTERRUPTIBLE
    - setup jump buffer and call schedule()
    |
    V
    schedule
        |
        V
        - __schedule(preempt: bool)
            - prev = rq->current
            - next = pick_next_task()
            |
            V
            - context_switch(rq, prev, next)
                |
                V
                - __switch_to(prev, next)
                    - set abs_prev
                    - change CPU ownership to next
                    - Wake lthread backing _next
                    - As prev has TIF_SCHED_JB flag set, long jump back.
    |
    V
    (back in threads_sched_jb())
```

The known usages of `thread_sched_jb` are - 

1. `switch_to_host_task(task)`: If `current` process context != task.
2. `lkl_cpu_put`: If the Linux scheduler run queue has >= 1 tasks.
3. `lkl_syscall`: If syscall is NR_REBOOT, yields to scheduler after running the syscall.

Usages 2. and 3. use `thread_sched_jb` are in the epilogue of `lkl_syscall`, and effectively allow the thread to invoke the schedule and relinquish the CPU lock.  

The `switch_to_host_task` usage is more involved and discussed next.

## switch_to_host_task(task)
`switch_to_host_task` function ensures that a task being passed as input parameter is the `current` process context.
If this is already the case the function returns early. Else, this causes transfer of control to the LKL scheduler so that it can schedule `task`. It does so using `thread_sched_jb`. 
Once the scheduler long jumps back, the thread sleeps on its scheduler semaphore and waits for the LKL scheduler to wake it.

Call graph for `switch_to_host_task` to `__switch_to` interactions:
```
switch_to_host_task(task: task_struct)
    // LKL CPU ownership and sched_sem wait/wake operations both work on the
    // lthread identity. As we want the current lthread to assume `task` 
    // identity, link them together.
    - task.ti.tid = lthread_self()
    - wake_up_process(task)
    |
    V
    - thread_sched_jb()
        - current.ti.flags = TIF_SCHED_JB
        - setup jump buffer and call schedule()
        |
        V
        ...
            - __switch_to(prev, next)
                - ...
                - As prev has TIF_SCHED_JB flag set, long jump back.
        |
        V
        (back in threads_sched_jb())
    |
    V
    (back in switch_to_host_task(task))
    - sem down on task's scheduler semaphore
    [[lthread sleeps and will be woken up when "task" is picked up by the LKL scheduler]]
    - schedule_tail(abs_prev)
```

# Pthreads support

## pthread_create
The libc code calls `clone()` to create a new thread.
There are two different types of integration points for LKL during process creation. (All of the following functions are defined in [`arch/lkl/kernel/threads.c`](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/kernel/threads.c)):
i) Setting up the arch specific thread_info struct.
    - `alloc_thread_stack_node()`
    - `init_ti()`
    - `setup_thread_stack()`
ii) Creating the host thread(lthread) backing the Linux task.
    - `copy_thread_tls()`

Call graph within LKL caused by pthread_create()->clone():
```
_do_fork(*args: kernel_clone_args)
    - ...
    |
    |
    V
    - copy_process(...,args)
        - ...
        |
        V
        - dup_task_struct(current, node)
            - ...
            |
            V
            - alloc_thread_stack_node(node, orig) // LKL arch specific
                - malloc thread_info.
                |
                V
                - init_ti() // LKL arch specific
                    - allocate scheduler semaphore.
                    - set some fields to zero values: dead, prev_sched, tid, cloned_child.
                - return pointer to thread_info.
            |
            V
            - setup_thread_stack(p, orig) // LKL arch specific
                - does no stack related setup.
                - copies some fields from orig - flags, preempt_count, addr_limit
        |
        V
        - copy_thread_tls(clone_flags, args->stack, args->stack_size,
                             p, args->tls) // LKL arch specific
            - if creating a thread via clone():
                - Set flags: TIF_HOST_THREAD and TIF_CLONED_HOST_THREAD
                - ti->tid = LKL host op for creating thread()
                - Set process name field "task_struct->comm"
                - Set ti.cloned_child for parent
                - return 0 on success or -ENOMEM
    |
    V
    - ...

```

After the clone() syscall is run, the state of newly created child process must be set as non-runnable in LKL. This in turn requires the child process be the `current` process context. If this wasn't enough there is one more complication here. For LKL to schedule the thread, it needs to transfer the CPU lock ownership to it. As mentioned earlier, the CPU lock is assigned by lthread id. So briefly the lthread identity of the parent is shared with the child thread. 

After setting the state as `TASK_UNINTERRUPTIBLE`, the lthread id for the child thread is restored.


## pthread_exit

A pthread issues a `SYS_exit` [here](https://github.com/lsds/sgx-lkl-musl/blob/c690dad8beb1a806b74aeb6db14420665cf90704/src/thread/pthread_create.c#L123), or if its detach attribute is set it exits [here](https://github.com/lsds/sgx-lkl-musl/blob/c690dad8beb1a806b74aeb6db14420665cf90704/src/thread/x86_64/__unmapself.s).

As part of the exit system call, the thread eventually yields to the LKL scheduler and sleeps on its scheduler semaphore [here](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/kernel/threads.c#L194).

At some later point, the LKL architecture specific integration point for thread cleanup - [`free_thread_stack`](https://github.com/lsds/lkl/blob/e041aa71e03a142ecef542c005b07d13e2a3b722/arch/lkl/kernel/threads.c#L126), is called from the `ksoftirqd` kthread. 

Stacktrace at the entry of `free_thread_stack`:
```
Thread 7 "ENCLAVE" hit Breakpoint 2, free_thread_stack (tsk=0x7fe03fdb8b80)
    at arch/lkl/kernel/threads.c:124
124     {
(gdb) bt
#0  free_thread_stack (tsk=0x7fe03fdb8b80) at arch/lkl/kernel/threads.c:124
#1  0x00007fe00008cdc7 in release_task_stack (tsk=<optimized out>) at kernel/fork.c:437
#2  free_task (tsk=0x7fe03fdb8b80) at kernel/fork.c:459
#3  0x00007fe00008d012 in __put_task_struct (tsk=0x7fe03fdb8b80) at kernel/fork.c:748
#4  0x00007fe0000906eb in put_task_struct (t=<optimized out>) at ./include/linux/sched/task.h:119
#5  delayed_put_task_struct (rhp=0x4) at kernel/exit.c:182
#6  0x00007fe0000c6103 in __rcu_reclaim (rn=<optimized out>, head=<optimized out>)
    at kernel/rcu/rcu.h:222
#7  rcu_process_callbacks (unused=<optimized out>) at kernel/rcu/tiny.c:103
#8  0x00007fe00064f240 in __do_softirq () at kernel/softirq.c:292
#9  0x00007fe00009290d in run_ksoftirqd (cpu=<optimized out>) at kernel/softirq.c:603
#10 0x00007fe0000acb57 in smpboot_thread_fn (data=0x7fe03fdb8b80) at kernel/smpboot.c:165
#11 0x00007fe0000a9304 in kthread (_create=0x4) at kernel/kthread.c:268
```

`free_thread_stack` in turn calls `kill_thread(ti: thread_info)`. For cloned host threads(pthreads are created via `clone()`), `kill_thread` marks `ti->dead` as true and wakes the threads scheduler semaphore. After this, it joins on that thread.

Meanwhile, the exiting thread wakes up inside `__switch_to`. It clears its TLS key storing its `task_struct` and calls the host op for thread_exit. This internally results in a yield to the lthread scheduler. 
Once back in the lthread scheduler, it wakes up the thread joined on it - the `ksoftirqd` kthread.

`ksoftirqd` kthread resumes in `kill_thread`. It clears the `tid` and `sched_sem` fields in the `thread_info` structure and returns to `free_thread_stack`.
The last thing `free_thread_stack` does is to free the `thread_info` structure corresponding to the exited thread. This marks the end of the threads journey within LKL.
