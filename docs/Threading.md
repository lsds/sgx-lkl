The SGX-LKL threading implementation
====================================

SGX-LKL has four kinds of threads: ethreads, lthreads, Linux tasks, and pthreads.
This document explains how they are implemented and how they relate.

Ethreads (enclave threads) are the lowest-level threads.
These are roughly analogous to VCPUs in conventional VMs.
In SGX, each ethread corresponds to a thread-control structure (TCS), allocated by [Open Enclave](https://openenclave.io/sdk/).

The lthreads layer provides a cooperative threading library on top of ethreads.
Each ethread runs an instance of the lthread scheduler, which pulls lthreads from a multi-producer, multi-consumer queue (MPMCQ) to run.
These threads run until they explicitly yield.

The Linux kernel (LKL) manages its own task abstraction.
LKL, unlike other Linux architectures, expects the host environment to provide a threading abstraction.
LKL associates each Linux task with a thread provided by its host environment ('host thread').
In the case of SGX-LKL, lthreads provide LKL's host thread implementation and so each Linux task is backed by an lthread.
The LKL documentation refers to 'host threads', these are lthreads in our use.

The userspace libc (musl) provides a POSIX threads (pthreads) implementation that sits atop Linux's tasks.
Each pthread is run by the lthread scheduler but may be caused to block by LKL.

Ethreads
--------

Ethreads are created by the host environment calling one of two ecalls, either [`sgxlkl_enclave_init`](https://github.com/lsds/sgx-lkl/blob/24467b08346cd7384eb93f845dec896a1d429711/src/enclave/enclave_oe.c#L395) (for the first ethread) or [`sgxlkl_ethread_init`](https://github.com/lsds/sgx-lkl/blob/24467b08346cd7384eb93f845dec896a1d429711/src/enclave/enclave_oe.c#L277) (for subsequent ethreads).
Each of these threads calls `lthread_run` to start an instance of the lthread scheduler.

The ethreads do not use the FS segment on x86-64.
The GS segment stores a pointer to the Open Enclave state and the lthread scheduler.
The [lthread context switch](https://github.com/lsds/sgx-lkl/blob/796b346d4762a93be7bfc2ba5ce97b9ab840a4bd/src/sched/lthread.c#L466) [switches the FS segment register](https://github.com/lsds/sgx-lkl/blob/796b346d4762a93be7bfc2ba5ce97b9ab840a4bd/src/sched/lthread.c#L411) and makes this available for higher layers in the threading stack.

LThreads
--------

The lthread library provides a *cooperative* threading model.
The code lives in the [src/sched](../src/sched) directory in the SGX-LKL repository.

### The main scheduler loop

The main loop for the scheduler is in the [`lthread_run`](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L214) function.
The function [pulls the next thread from the run queue](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L234) and then [calls `_lthread_resume`](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L242).

The [`_lthread_resume`](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L453) function does most of the work for running a thread.
`_lthread_resume` sets up the initial thread state if required and then calls [`_switch`](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L482), a short assembly routine that saves all registers that are preserved across function calls and restores the same set of registers from a buffer.
The `_switch` routine [restores the stack pointer](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L147) of the thread being switched to and pushes the new instruction pointer value onto the new stack.

If the thread is a new thread, its instruction pointer was [set during thread initialisation](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L540).
If the thread has previously yielded, the instruction pointer is the [return address for the `_switch` call that switched away from the lthread](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L134).

Note that `_switch` does *not* switch between two arbitrary lthreads.
One of the threads involved in a `_switch` call is always the scheduler.
The `_switch` call in `_lthread_resume` switches to another thread, the call [in `_lthread_yield_cb`](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L340) and [in `_lthread_yield`](https://github.com/lsds/sgx-lkl/blob/47a5f0e718badfa85694a9de6222af41d9bfbb84/src/sched/lthread.c#L346) switch back to the scheduler.

After the running lthread yeidds, `lthread_run` checks whether any sleeping threads (those blocked waiting for event channels or futexes) are runnable and, if so, adds them to the queue.

`lthread_run` maintains a count of consecutive loop iterations in which there were not runnable lthreads.
Once this reaches a threshold, the scheduler issues an ocall that suspends execution of the ethread until either an event channel is signaled or a timeout expires.

`lthread_run` exits the loop and returns only when the enclave is terminating.
### Locking

There are two primitives for building locks in the lthreads implementation.
Ticket locks are spinlocks, futexes provide a fast path using atomic operations but then sleep.

#### Ticket locks

Ticket locks are spinlocks.
They are defined and documented in [src/include/enclave/ticketlock.h](../src/include/enclave/ticketlock.h).
A thread acquiring a ticket lock will spin in a compare and swap (CAS) loop until it successfully acquires the lock.
If an lthread yields while holding a ticket lock, there is a chance of deadlock because the next thread to try to acquire the lock will spin in a CAS loop and not yield.
This may, in turn, prevent the thread holding the lock from being able to run.
In the simplest case, consider a system running with a single ethread.
If a thread yields while holding a ticket lock, the next thread that attempts to acquire the same ticket lock will spin and not yield to the scheduler.
The first thread is never rescheduled and so cannot release the lock.
Similar situations can occur with multiple ethreads if more than one lthread attempts to acquire ticket locks held by yielded lthreads.

Ticket locks are used to implement some parts of the lthread scheduler.
This means that there is no way for them to be made to yield in their spin loop.
Looking at the ticket lock code in isolation may lead you to believe that this limitation could be removed by adding a yield call in the the CAS loop.
This is not possible because yielding transfers control from the current lthread to the scheduler.
If the caller is the scheduler then there is no associated lthread that can yield.

#### Lthread futexes

The lthread futex implementation is a simplified version of the Linux `futex` system call.
A futex is a 32-bit word that can be used to hold state used to implement arbitrary locking primitives.
On the fast path, all updates to the futex word are done by CPU atomic operations.
For example, a mutex could be implemented by treating a value of 0 as unlocked and a value of 1 as locked, with a CAS changing the state from 0 to 1 to acquire the lock on the fast path.
The futex calls handle the slow path, where one or more threads need to wait.

The `enclave_futex_wait` call suspends the calling thread until another thread makes a corresponding `enclave_futex_wake` call for the same futex word address, or until a timeout specified by the caller is reached.
The futex system is responsible for ensuring that wake-up events are not lost and so acquires a global lock and then checks that the expected value is still present at the memory location.
This lock ensures that a `enclave_futex_wake` call either happens after the `enclave_futex_wait` has sent the calling thread to sleep or happens before and prevents the thread from sleeping.

The threads suspended by `enclave_futex_wait` are stored in a linked list, threaded through the thread pointers.
A `enclave_futex_wait` call can return (waking up the sleeping thread) as a result of one of two things.
Either a `enclave_futex_wake` acquires the lock, finds a waiting thread, and schedules it, or the `futex_tick` call triggers the timeout.

The lthread scheduler calls `futex_tick` in between scheduling threads to wake up any sleeping threads that have timed out.
This tries to acquire the ticket lock but returns immediately if it fails.
This can happen only if a thread is currently doing a futex call or if another thread is handling the tick.

#### LKL host interface synchronisation primitives

The futex code is used in [src/lkl/posix-host.c](../src/lkl/posix-host.c) to implement two synchronisation primitives for use by LKL.
These are not currently used anywhere else, though that may change in the future.

##### `lkl_mutex`

The `lkl_mutex` is a recursive or non-recursive mutex.
It uses the futex word to store one of three states: unlocked, locked but with no waiters, locked with one or more waiting threads.
When a thread tries to lock the mutex, it first tries a CAS to atomically transition from the unlocked to locked-but-no-waiters state.
If this fails, the lock is already in one of the locked states.
If this is a recursive mutex, then it's possible that this is an attempt to recursively acquire it, so the lock routine checks that the mutex owner is the current thread and simply increments the number of recursive acquisitions if this is the case.

If the lock is held but no other threads are waiting, this thread does an atomic exchange to move the futex word to the locked-with-waiters state.
The result of the exchange contains the previous state of the mutex.
If the exchange moved from the unlocked state, the lock routine tries again to acquire the lock.
If the exchange moved from one of the locked states, the lock routine waits on the futex word with the expected state of locked-with-waiters.
When the futex call returns, it retries the atomic exchange.

On the unlock path, recursive mutexes simply decrement their recursion count until they are in the same state as a non-recursive mutex.
The final unlock then does an atomic fetch-and-decrement on the futex word.
This gives the old state.
If this decrement transitioned from the locked-with-no-waiters state, there is nothing more to do.
If the decrement instead transitioned from the locked-with-waiters state, the unlock routine transitions explicitly to the unlocked state and then calls `enclave_futex_wake` to wake up all waiters.

##### `lkl_sem`

The `lkl_sem` is a trivial counting semaphore.
This is analogous to a bucket of semaphore flags controlling access to a resource such that you can proceed when you have a flag and must wait if there are no flags available.
The `sem_down` function acquires a flag, blocking if one is not available.
The `sem_up` function returns a flag (which may or may not have been previously acquired) and wakes up any waiting flags.

These use the futex word to hold the semaphore value.
The down operation reads the count and, if the count is not zero, does a CAS to try to decrement it.
If the CAS fails or the initial value was zero, it then calls `enclave_futex_wait` with an expected value of 0 to wait until the value is non-zero.
When `enclave_futex_wait` returns, this process repeats.

The up operation is simpler.
It does an atomic fetch-and-increment operation.
If the transition is from zero to one then there may be waiters so it then calls `enclave_futex_wake` to wake them up.

This implementation is not very efficient and could be improved.

Linux tasks
-----------

Linux tasks are entities that the Linux kernel can schedule.
Each Linux task is backed by an lthread.
When it is executing in the kernel, the Linux scheduler is responsible for controlling whether it can run.
The kernel is compiled in non-SMP mode and so assumes that only one task can run at any given time.
When a task exits the kernel (for example, by returning from a system call), its scheduling is managed entirely by lthreads.

LKL uses a semaphore associated with each thread to allow the scheduler to suspend and wake threads.
The [`__switch_to`](https://github.com/lsds/lkl/blob/385f721b339fe48b188b4924c2663e1ea2cdeb13/arch/lkl/kernel/threads.c#L145) routine in LKL causes the calling thread to block by doing a `sem_down` operation on the current thread's semaphore after waking up the next thread by doing a `sem_up` on its semaphore.
This allows the kernel scheduler to pause execution of tasks and wake only a single task in the kernel at any given time.

The task associated with an lthread is stored using the `lthread_setspecific` function, analogous to `pthread_setspecific`.
When an lthread enters the kernel, the syscall handler first acquires the CPU lock.
It then looks up the task associated with this thread, lazily allocating one if required.
At this point, the kernel scheduler and the lthread scheduler may have different views of which thread is running.
LKL's [`switch_to_host_task`](https://github.com/lsds/lkl/blob/385f721b339fe48b188b4924c2663e1ea2cdeb13/arch/lkl/kernel/threads.c#L199) routine is responsible for synchronising these states.
This first marks the desired task as runnable and then runs the scheduler until it gets to that task.
This time, `__switch_to` routine does a [long jump](https://github.com/lsds/lkl/blob/385f721b339fe48b188b4924c2663e1ea2cdeb13/arch/lkl/kernel/threads.c#L170) back out of the scheduler, leaving the expected thread as the currently running one.

When a thread leaves a system call handler, its task is left in the `TASK_UNINTERRUPTIBLE` state.
This prevents the Linux scheduler from attempting to reschedule it.
It can then run, outside of the kernel, for as long as possible.

Pthreads
--------

POSIX threads are implemented by libc on top of the Linux `clone` system call.
The `clone` call sets up a new thread given a program counter, stack pointer, and TLS pointer.
The TLS pointer provided on creation ends up in the FS register and is used to manage all state associated with the pthreads layer, along with any userspace thread-local storage.
