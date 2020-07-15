Incompatibilities between SGX-LKL and x86-64 Linux
==================================================

SGX-LKL is a port of Linux to a paravirtualised SGX environment, using LKL as a porting layer.
SGX-LKL runs x86-64 programs and these programs execute the same machine instructions as they would outside of an enclave.
The kernel; however, runs in quite a different environment to ring 0 on an x86-64 CPU and this can lead to some important differences.

Compatibility differences
-------------------------

Some features are not supported at all and so applications that depend on them will not work.

### Single process

The SGX-LKL environment provides a single process due to the lack of certain virtual memory features inside SGX enclaves.
Any application that depends on spawning child processes will not work.

In some future version, we expect to be able to support multiple processes but there will be no isolation between them.
This means that using multiple processes for privilege separation will not be possible.

### No MMU support

A conventional x86-64 system exposes multiple privilege domains ('rings') and provides a memory management unit (MMU) that allows each userspace process to have a separate virtual address space.
This includes the ability to alias pages such that the same physical page is in several different locations in the virtual address space.
In contrast, SGX exposes a single virtual address space and does not allow page mappings to be modified.

At the system call layer, this means that there are some restrictions on `mmap`:

 - Shared mappings (`MAP_SHARED`) are not automatically written back.
 - Fixed mappings (`MAP_FIXED`) should only be done over existing mappings: the kernel and userspace share an address space.
   It is currently possible to do `MAP_FIXED` over kernel mappings, this will be fixed in a future version.

These restrictions are close to those of uCLinux and SGX-LKL will eventually use the no-MMU code from Linux.

Because SGX does not grant control over the MMU, it is impossible on SGX1 hardware to securely change page permissions.
SGX-LKL delegates this to the untrusted host.
As a result, any `mprotect` call, or any `mmap` with permissions weaker than read-write-execute, should be considered advisory.
These calls will work correctly *in the absence of an attacker* but a malicious host can simply ignore these calls.
This will be addressed on hardware with Enclave Dynamic Memory Management (EDMM) support.

### Cooperative threading

The SGX-LKL runtime uses an enclave thread (ethread) abstraction that roughly corresponds to a virtual CPU (VCPU) in a conventional VM environment.
In a conventional Linux system, the Linux scheduler runs userspace threads, switching to another thread either when a thread makes a blocking system call or when an interrupt fires.
SGX; however, does not provide a mechanism for receiving timer interrupts and so cannot efficiently run a preemptive scheduler.

SGX-LKL uses a cooperative scheduler ('lthreads') to provide a cooperative threading implementation, multiplexing cooperative lthreads on top of hardware enclave threads ('ethreads').
The lthread scheduler running on each ethread will switch the running lthread on any system call.
The main impact of this on userspace code is that threads that run without any system calls will not be interrupted and can consume all of the CPU resources.
Spin locks that do not have a fallback futex path for the contended case, for example, may fail to make progress when there is a single ethread and may consume excessive amounts of CPU time in all uses.
Threads that block on a futex will be correctly scheduled.

LKL runs Linux in single-core mode and delegates scheduling of userspace threads to the lthread scheduler.
This means that only one core can be executing system calls at any time, though userspace code can be executing on other cores at the same time.
As a result, the kernel's CPU affinity modes are not supported.
Attempting to set CPU affinity will report success but silently fail.

### Calling system calls

On x86-64 Linux, userspace makes system calls by placing the arguments and system call number in registers and then issuing a `syscall` instruction.
With SGX, the `syscall` instruction is not permitted and so will raise an illegal instruction trap.
The trap will be delivered to the host, resulting in an enclave exit and an enclave resume with the host.
We do not yet emulate the syscall instruction and so any code that attempts to make system calls directly will fail.

The libc `syscall` function has been modified to use the LKL system call mechanism and so any code that does system calls via this function will work.


Performance differences
-----------------------

The performance characteristics of SGX-LKL differ from those of a conventional Linux system.
These are not strictly incompatibilities because they will not prevent programs from running but they may prevent programs from making progress at an acceptable rate.

### Working set limits

SGX, in current implementations, uses an encrypted page cache (EPC) that is directly accessible and guarantees confidentiality and integrity.
Accesses in the EPC are slightly slower than normal memory.
If the EPC is exhausted, the OS must swap to the rest of memory.
This involves encrypting a page, removing it from the enclave, and providing a different page, which is then decrypted and validated.
This process takes tens of thousands of cycles.

Any workload that does not fit into the EPC will incur a significant (often a factor of ten) slowdown as a result of EPC swapping overheads.
In the most recent shipping SGX hardware, such as the Coffee Lake Xeons in the Azure DCv2 VMs, the EPC is 256MiB, shared between all SGX enclaves.
On older hardware, the EPC is 128MiB.

### Slow instructions

Some instructions are not permitted in SGX enclaves.
The two that are likely to be used from userspace applications are:

 - `cpuid`, which queries information about the current CPU and its configuration.
 - `rdtsc`, which queries the current timestamp counter.

When these instructions are issued, SGX will abort and the host kernel will trigger an illegal instruction trap to userspace.
The userpace signal handler will reflect this trap back into the SGX enclave.
SGX-LKL will check if the faulting instruction is `cpuid` or `rdtsc` and emulate them but will generate a `SIGILL` for any other instruction.

A malicious host can cause spurious illegal instruction, floating point, or segmentation fault signals to be delivered.

### Imprecise time

SGX does not give a trusted time source and, as described above, the `rdtsc` instruction is not allowed.
SGX-LKL uses a variable in untrusted memory to provide a monotonic counter.
The host updates this periodically (approximately every 500μs, subject to host scheduler variation) and the enclave code advances it by 1ns on every query if the host has not changed the update.
The in-enclave code ensures that the monotonic counter always goes forward.
This means that the clock source provided to the in-enclave kernel will always go forward but may jump forward.
Software running on the kernel is still free to set the wall-clock time to any value.
All of the Linux clocks are driven from the monotonic counter, so anything depending on smooth time (e.g. video / audio playback) would not be reliable.

Additionally, the time exposed in the enclave is untrusted.
The enclave may communicate with an external trusted time source but that can give only a lower bound on the current time: a malicious host could cause the enclave to sleep for an unbounded amount of time.

Summary of security implications
--------------------------------

Some of the differences above can lead to security implications.
The SGX threat model assumes that the host may be malicious but that a malicious host should not be able to compromise the confidentiality or integrity of the enclave.
The host is assumed to be able to compromise availability (it can always refuse to schedule any enclave threads).

The lack of control over the MMU means that any software that depends on changing page permissions and receiving `SIGSEGV` for violations may be incorrect.
The host (in the absence of EDMM) can always fail to change the permissions and prevent the traps from being delivered.

The host is responsible for reflecting all hardware traps (segmentation faults, floating-point exceptions, and illegal instruction exceptions) to the enclave.
The host can therefore always trigger these spuriously.
Most software does not handle these and so SGX-LKL will simply kill the process, affecting availability but not confidentiality or integrity.
If a process does handle these, it must ensure that it can handle spurious traps.

Time is untrusted in the enclave.
A malicious host cannot make time run backwards, but they can make it advance very slowly.
Applications running on SGX-LKL must be resilient to their perceived time advancing more slowly than the real world.
