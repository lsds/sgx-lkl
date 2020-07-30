Frequently Asked Questions
==========================

What is SGX-LKL?
----------------

SGX-LKL is a port of Linux along with additional code to allow x86-64 Linux applications to run inside an enclave.
Intel SGX, the first enclave technology to be supported, provides an isolated (encrypted) region within a process's address space that cannot be read or modified from the outside (including by the untrusted host OS kernel or hypervisor). 
SGX-LKL executes Linux inside the enclave in a single-address-space mode similar to uCLinux, with a simple paravirtualized VM-like interface to the surrounding process.

The project began at Imperial College London and has since been developed jointly by Imperial College London and Microsoft Research.
It is now also supported by Microsoft's Azure Confidential Computing (ACC) team.

What is the relationship between this project and Linux/LKL?
------------------------------------------------------------

The Linux kernel library is an out-of-tree architecture port to allow some or all of the Linux kernel to run in virtual environments.
This project uses LKL to port Linux to run inside SGX enclaves.
LKL is our direct upstream, and we are working with the LKL project to upstream any of our changes that are valuable to other members of the Linux community.
Our friendly fork of LKL is a staging point for all of our changes and we are committed to working with the LKL project to contribute these changes.

LKL is, itself, in the process of being contributed to the Linux project.
Once this is completed, Linux becomes our direct upstream.

What is the relationship between this project and Open Enclave?
--------------------------------------------------------------

This project uses Open Enclave to provide an abstraction layer over trusted execution environments and depends on Open Enclave for several key features:

- Creating an enclave and loading a binary image
- Creating attestation quotes over the enclave contents
- Defining synchronous enclave entry and exit points
- Delivering synchronous exceptions (e.g. illegal instruction traps) into the enclave

Why isn't this part of upstream Linux?
--------------------------------------

Much of this effort is highly specific to TEEs in general, and the SGX environment in particular, and we are prototyping some features that work with vendor-specific cloud services.
We do not wish to claim that we have the correct abstractions for these until we have at least two examples.
We regard Linux as one of our (indirect) upstream sources and are very happy to contribute changes that we have made to any of our upstream components if their respective communities find them useful.

Some parts, such as the launcher and the host side of the interface, are not specific to Linux. 
These are released under the MIT license to make it possible for any other open source operating system to use them.
We welcome contributions to support other systems.

How big is the host interface?
------------------------------

The host interface is intentionally small and reuses existing well-tested drivers where possible.
On setup, there is a single synchronous call to each enclave thread (roughly: VCPU) to start it running and allow the scheduler to begin working.
The first call provides configuration information including the location of VirtIO ring buffers and descriptor tables.
We then use existing VirtIO network, block, and console device drivers for communicating with the outside world (the console driver is untrusted and should be used only for debugging).
We add a paravirtualised clock source, which exposes an in-memory monotonic counter, with the monotonicity guarantee enforced by the enclave.
We also provide a small number of synchronous calls ("ecalls" in SGX terminology, analogous to hypercalls in a conventional VM system):

- Change the permissions of a page.  
  Currently, SGX1 does not allow the enclave to verify that these changes have taken place. 
  SGX2 includes Enclave Dynamic Memory Management (EDMM) and will make this secure.
- Pause an enclave thread until either an amount of time has elapsed or a device signals readiness. 
  This is used, for example, to allow an enclave to sleep without consuming CPU cycles until a network packet arrives.

If an enclave thread encounters a synchronous CPU exception, this is delivered outside of the enclave and then reflected back (just as with a paravirtualised VM).
The information about this exception is untrusted.

The host interface is [documented](HostInterface.md).

Can I use a Confidential Linux Container on a normal Linux system?
------------------------------------------------------------------

A Confidential Linux Container simply contains one or more regular Linux filesystem images, which rely on Linux DeviceMapper functionality for encryption and integrity protection. 
You can mount the disk images via the loopback device on any Linux system, as long as you have access to the encryption keys. 
In cloud deployments, the keys for encrypting the filesystem are expected to be stored in a secure key store, protected by a key-release policy dependent on the attestation and so can be released only in accordance with the policy set by the user.
If you have created an image and have the decryption key, you can mount it anywhere. 
If the root filesystem uses only `dm-verity` to provide integrity but no confidentiality guarantees, you can mount it anywhere but you may not be able to access other encrypted read/write filesystems with confidential data.

How compatible is this with x86-64 Linux?
-----------------------------------------

We aim for 100% compatibility, within the constraints of the environment.
This is a port of Linux and so should have the same behaviour as Linux when not hitting hardware-dependent code paths.

There are two significant differences between this port of Linux and x86-64 Linux:

- We are unable to receive timer interrupts for preemption and so all scheduling is cooperative.
- We do not have access to page tables for virtual memory mappings.

The former means that threads that run for a long time without doing any system calls or yielding explicitly will not be preempted.
Anything that uses the `futex` system call will correctly yield (all system calls are yield points and so most code is unaware of this).

The second point means that we are unable to support kernel isolation, fork, and most complex uses of `mmap` and related APIs.
Single-process containers should work; however, we have full networking support (including a WireGuard VPN) and so users can assemble complex systems from microservices.

What are the known security weaknesses of the current design?
-------------------------------------------------------------

We assume that everything outside of the enclave is untrusted.
An attacker is able to modify data coming from the block device or modify network packets and so we recommend using encryption with integrity protection for both (for example, by default the base container image is a read-only filesystem protected with dm-verity, for strong integrity guarantees and the default network interface uses the Linux Wireguard VPN for end-to-end encryption and integrity protection).

In contrast, everything inside the enclave is in a single trusted security context.
We are not, with existing enclave hardware, able to isolate the kernel from userspace.
This provides a similar model to uCLinux, where userspace and the kernel are in the same address space.

The host OS can (with SGX 1) modify page permissions without the enclave's permission.
Spurious page faults can allow single stepping.
Some programs depend on receiving SIGSEGV for correctness (for example, some garbage collectors use this to detect changes to a page).
A malicious OS can leave pages read-write-execute, which avoids the signals being delivered, potentially corrupting enclave state.

SGX does not provide a trusted time source.
The SGX-LKL runtime guarantees that time runs forwards, but an attacker can make time appear to pass more slowly than it should.
Confidential containers must ensure that they are safe in the presence of wall-clock time running backwards.

The host is trusted for availability: it can always simply fail to schedule enclave threads.

Side channels and other hardware vulnerabilities in the underlying enclave technology may weaken some of our security guarantees.
