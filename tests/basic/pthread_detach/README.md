# Important LKL functions related to process scheduling

## switch_to_host_task to __switch call graph
```
switch_to_host_task(task: task_struct)
    - task.ti.tid = lthread_self()
    - wake_up_process(task)
    |
    V
    - thread_sched_jb()
        - current.ti.flags = TIF_SCHED_JB
        - current.state = TASK_UNINTERRUPTIBLE
    (jump to scheduler)
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
                    - change cpu ownership to next
                    - Wake lthread backing _next
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

## thread_sched_jb
`thread_sched_jb` is LKL's way of doing co-operative multitasking, by yielding to the scheduler. Its invoked from - 

1. `lkl_cpu_put`: If the Linux scheduler run queue has >= 1 tasks.
2. `switch_to_host_task(task)`: If `current` process context != task.
3. `lkl_syscall`: If syscall is NR_REBOOT, yields to scheduler after running the syscall.

# Pthreads support

## pthread_create

```
_do_fork(*args: kernel_clone_args)
    - ...
    |
    |
    V
    - copy_process(...,args)
        - ...
        | // where is current picked from?
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