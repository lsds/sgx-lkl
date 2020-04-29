Host interface
==============

This document describes the interface between a library OS running in the an enclave and the untrusted host environment.
SGX-LKL includes this host environment and a port of Linux to run in this environment.
This interface is designed to work in an SGX-like abstract machine, which provides:

 * Synchronous function-call-like domain transitions, which may have a high latency.
 * Isolated memory for the library OS, which is not visible to the host.
 * Untrusted shared memory, visible to the library OS and the host.
 * A fixed number of virtual CPUs running library OS code.

Anything outside of the guest's isolated memory is untrusted by the guest for confidentiality and integrity.

Design goals and constraints
----------------------------

The interface is intended to be similar to a legacy-free lightweight paravirtualised interface, extended with attestation support.
Where possible, existing code paths in the library OS should be used.

The target environments differ from most VM interfaces in several respects:

 * Calls from the library OS to the host (the equivalent of hypercalls) must flush large amounts of microarchitectural state to preserve [Confidential Computing guarantees](https://confidentialcomputing.io/faq/) and so are orders of magnitude more expensive than hypercalls.
   As such, minimising the number of them is critical for performance.

 * The guest cannot grant access to its own memory to the host, shared memory must be configured by the host.

Additionally, there are some limitations that are specific to SGX (some specific to SGX1):

 * The guest cannot change page protections.
 * There is no trusted time source in the guest.
   Time is provided from the host via a mechanism detailed below in the Time section.

The design is intended to both support SGX efficiently and to be adaptable to future TEE technologies.

Concepts
--------

The launcher is responsible for loading an image into memory along with any configuration data required by the system.
As such, it subsumes the roles of boot firmware, second-stage loader, and bus enumeration.
The equivalents of PCI device or ACPI table enumeration are replaced with a structure passed into the library OS on launch.
This structure contains all of the configuration data related to the current instantiation.

After launch, there are three main mechanisms for communicating between the host:

 * *Virtual devices* implement paravirtualised devices in shared memory.
 * *Event channels* provide an equivalent of interrupts.
 * *Synchronous calls* provide a hypercall-like mechanism and an upcall-like mechanism.


High-level overview
-------------------

On startup, the launcher loads a library OS image with a well-known entry point for starting (an "ecall" in SGX).
The launcher then invokes this entry point with information containing the number, kind, and locations of all virtual devices, and their associated event channels.
Each additional virtual CPU ("ethread", in SGX terminology) is then started by an explicit invocation.

The library OS then attaches each device and configures event channels.
Each device has one or more host threads associated with it, but these will typically be blocked waiting for input.
The host OS scheduler is responsible for multiplexing the threads that handle virtual devices with the threads that back VCPUs.

The host interface is intended to run in a polled mode, where the only context switches are as a result of the host scheduler multiplexing threads on physical CPUs (or hypervisor-provided VCPUs).
The device threads will process requests and respond, without any explicit exits.
In contrast, in an I/O-bound mode when the guest has no work to do, it should not busy wait and should explicitly exit and invoke the device threads.

If the guest has no work to do, its scheduler is expected to invoke a synchronous call, specifying wakeup criteria.
The host thread then sleeps, parking the VCPU.
Any event channels that are signalled will cause this thread to wake and return execution to the guest.
This allows, for example, network services to sleep until a packet arrives and then enter a polling mode while the network stream is active.

Startup
-------

**TO DO**: This structure is still being extended as the VirtIO integration stabilises.

The launch process loads the library OS into the guest and then calls two entry points, defined by the following EDL definitions:

```
public void sgxlkl_enclave_init([in] sgxlkl_config_t* conf);
public void sgxlkl_ethread_init(void);
```

The first is called once on a single VCPU and is used to perform initial setup, device mapping, and so on.
The second entry point is called once for each additional VCPU.

These calls are expected to return only when the enclave exits.

Event channels
--------------

Because domain transitions are expensive, even in comparison with system calls or hypercalls, the event channel mechanism is designed to be run primarily in a polled mode.
Event channels are implemented using a simple futex-like single-waiter model.
Each event channel is implemented as a 64-bit word.
The low bit indicates whether there is a waiter, the remaining 63 bits indicate the number of events delivered.
Assuming one event is delivered per cycle on a 4 GHz machine, this counter will not overflow for 73 years.

The sequence for delivering an event is as follows:

 1. Perform an atomic add 2 to the event channel.
 2. Inspect the old value.
 3. If the low bit is set, invoke the waiter via a synchronous call.

Polling an event channel is a simple case of reading the value and comparing the high 63 bits to a previous value.
Waiting for an event involves the following steps:

 1. Read the value.
 2. Increment the read value.
 3. Perform a strong compare and exchange, inserting the value from step 2 if the value from step 1 is present.
 4. If the compare and exchange failed, a new event has been delivered, so return immediately.
 5. If the compare and exchange succeeded, perform a synchronous call to wait.

It is the responsibility of the callee of the synchronous call to implement sufficient locking to avoid losing wake events.
The host side achieves this by acquiring a lock, re-checking the event channel, and then sleeping on a condition variable.
Any host threads that deliver wakeups acquire the same lock, signal the condition variable, and then release the lock.

Virtual devices
---------------

The virtual devices conform to the VirtIO specification, using the MMIO variant, with the exception that all synchronous communication is via event channels.
Writes to the NOTIFY memory offsets in the MMIO region are expected to be translated into writes to an event channel by the library OS.
Similarly, interrupts are delivered via event channel and so are expected to be polled by a cooperative schedluer in the guest, if the guest is running.

If the guest has suspended the VCPU that is waiting for an event channel then the host is responsible for resuming that VCPU when an event is delivered.

For typical use, every guest has at least one block device containing the application and its dependencies and typically at least one network device.
All devices are untrusted and it is the responsibility of the guest to use sufficient encryption for the confidentiality and integrity guarantees that the workload requires.
For debugging, there is also a console device but because this is entirely unencrypted it should be disabled in any production deployment.

Signal handling
---------------

SGX does not yet provide a mechanism for trusted delivery of synchronous exceptions into an enclave.
As a result, any trap results in an enclave exit and a signal is delivered to the host.
The host interface does not provide anything beyond the Open Enclave vectored exception mechanism for signal delivery.

SGX-LKL registers a vectored exception handler with Open Enclave and injects the register state into LKL as if it were a CPU trap frame.
The guest is responsible for validating any exceptions that are delivered by this mechanism because the source is untrusted.

Synchronous calls
-----------------

The host interface has a minimal set of synchronous calls, implemented in SGX as ecalls.
This part of the interface is intentionally small for both security and performance.

Once the guest has launched, there are no upcalls (ecalls in SGX terminology) from the host.
VCPUs may sleep for a defined period of time by calling:

```
void sgxlkl_host_nanosleep(size_t sleeptime_ns);
```

This parks the guest's VCPU and resumes after the specified amount of time has elapsed or until an event has delivered, whichever happens first.
Note that the guest cannot guarantee anything about the amount of time that this will actually sleep.

Time
----

The passage of time is provided to the enclave via shared data structure that is set up by the host on startup.
The shared data structure, `timer_dev`,

```c
struct timer_dev
{
    uint64_t version;
    _Atomic(uint64_t) nanos;
    uint64_t init_walltime_sec;
    uint64_t init_walltime_nsec;
};
```

`timer_dev` has a field `nanos` that indicates the number of monotonic nanoseconds that have passed since startup.
An instance of `timer_dev` is initialized on startup and updated periodically from outside the enclave to reflect the passage of time.
`nanos` can be accessed from within the enclave to create a monotonic source of time.

Inside the enclave, an internal "source of truth" for monotonic passage of time is also kept.
When an enclave caller needs access to the latest monotonic time, the following general logic occurs:

- If monotonic time outside the enclave is greater than monotonic time inside the enclave, then internal time is set to external time.

Wallclock time within the enclave is provided by setting the wallclock on enclave startup to a time approximately the same as the host.
Wallclock time inside the enclave can then move based on the corresponding movement of the monotonic nanoseconds as described earlier in this section.
`init_walltime_sec` and `init_walltime_nsec` are used to convey **on startup** the hosts perceived wallclock time.
Note, with the current version of this interface, it should be assumed that `init_walltime_*` fields are set only once.
Software running inside the enclave can use standard system calls such as `clock_settime` to change the wallclock time.
So for example, NTP would be able to function within the enclave.
However, the `init_walltime_*` fields are not updated by changes to wallclock time within the enclave.

Future plans
------------

The current design involves several copies for network packets.
On host systems that support device pass-through and kernel-bypass networking, we should be able to use DPDK or similar from inside the enclave directly.
