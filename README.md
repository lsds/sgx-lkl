SGX-LKL
=======

SGX-LKL is a library OS designed to run unmodified Linux binaries inside SGX
enclaves. It uses the Linux Kernel Library (LKL) (https://github.com/lkl/linux)
to provide mature system support for complex applications within the enclave. A
modified version of musl (https://www.musl-libc.org) is used as C standard
library implementation. SGX-LKL has support for in-enclave user-level
threading, signal handling, and paging. System calls are handled within the
enclave by LKL when possible, and asynchronous system call support is provided
for the subset of system calls that require direct access to external resources
and are therefore processed by the host OS. The goal of SGX-LKL is to provide
system support for complex applications and managed runtimes such as the JVM
with minimal or no modifications and minimal reliance on the host OS.


Prerequisites
---------------------------------

SGX-LKL has been tested on Ubuntu 16.04. To run SGX-LKL in SGX enclaves, the
Intel SGX driver (available at https://github.com/01org/linux-sgx-driver and
https://01.org/intel-software-guard-extensions/downloads) is required. We
have tested SGX-LKL with driver versions 1.9 and 2.0. SGX-LKL also provides
a simulation mode for which no SGX-enabled CPU is needed. Furthermore the
following packages are required to build SGX-LKL:
`make`, `gcc`, `bc`, `python`, `xutils-dev` (for `makedepend`).

Install these with:

```
sudo apt-get install make gcc bc python xutils-dev
```

Compilation has been tested with version 5.4 of gcc. Older versions might lead 
to compilation and/or linking errors.

### Networking support

In order for SGX-LKL application to send and receive packets via the network, a
TAP interface is needed on the host. Create it as follows:

```
sudo ip tuntap add dev sgxlkl_tap0 mode tap user `whoami`
sudo ip link set dev sgxlkl_tap0 up
sudo ip addr add dev sgxlkl_tap0 10.0.1.254/24
```

SGX-LKL will use the IP address `10.0.1.1` by default. To change it, set the
environment variable `SGXLKL_IP4`. The name of the TAP interface is be set
using the environment variable `SGXLKL_TAP` respectively.

The interface can be removed again by running the following command:

```
sudo ip tuntap del dev sgxlkl_tap0 mode tap
```

### SGX HW support

SGX-LKL supports non-PIE binaries, but in order to do so needs to be able to
map to address 0x0 of the virtual address space. Non-PIE Linux binaries by
default expect their `.text` segments to be mapped at address 0x400000. SGX
requires the base address to be naturally aligned to the enclave size.
Therefore, it is not possible to use 0x400000 as base address in cases where
the enclave is larger than 4 MB (0x400000 bytes). Instead, the enclaves needs
to be mapped to address 0x0 to adhere to the alignment requirement. By default,
Linux does not allow fixed mappings at address 0x0. To permit this, run:

```
    sysctl -w vm.mmap_min_addr="0"
```

To change the system configuration permanently use:

```
    echo "vm.mmap_min_addr = 0" > /etc/sysctl.d/mmap_min_addr.conf
    /etc/init.d/procps restart
```


Building SGX-LKL
----------------

### Hardware mode

To build sgx-lkl in hardware mode run:

```
    make
```

### Simulation mode 

To build sgx-lkl in simulation mode run:

```
    make sim
```

### Debug build

To build sgx-lkl with debug symbols and without compiler optimizations run
`make` with `DEBUG=true`:

```
# HW mode
make DEBUG=true
# Sim mode
make sim DEBUG=true
```


Running applications with SGX-LKL
---------------------------------

### General

To run applications with SGX-LKL, they need to be provided as part of a disk
image. Since SGX-LKL is built on top of musl, applications are expected to be
dynamically linked against musl. musl and glibc are not fully
binary-compatible. Applications linked against glibc are therefore not
guaranteed to work with SGX-LKL. The simplest way to run an application with
SGX-LKL is to use prebuilt binaries for Alpine Linux, which uses musl as its C
standard library.

### JVM

A simple Java HelloWorld example application is available in
`apps/jvm/helloworld`. To build the disk image, run

```
    make
```

This will compile the HelloWorld Java example, create a disk image with an
Alpine mini root environment, add a JVM, and add the HelloWorld.class file.

To run the HelloWorld java program on top of SGX-LKL inside an enclave, run

```
../../../tools/sgx-lkl-java ./sgxlkl-java-fs.img HelloWorld
```

`sgx-lkl-java` is a simple wrapper around `sgx-lkl-run` which sets some common
JVM arguments in order to reduce its memory footprint. It can be found in the
`<sgx-lkl>/tools` directory.


### Running applications from the Alpine Linux repository

Alpine Linux uses musl as its standard C library. SGX-LKL can support a large
number of unmodified binaries available through the Alpine Linux repository.
For an example on how to create the corresponding disk image and how to run the
application, the example in `apps/miniroot` can be used as a template. Running

```
make
```

will create an Alpine mini root disk image that can be passed to sgx-lkl-run.
`buildenv.sh` can be modified to specify APKs that will be part of the disk
image. After creating the disk image, applications can be run on top of SGX-LKL
using `sgx-lkl-run`. Using redis as an example (the APK `redis` is listed in
the example `buildenv.sh` file in `apps/miniroot`), redis-server can be
launched as follows:

```
SGXLKL_TAP=sgxlkl_tap0 SGXLKL_VERBOSE=1 ../../../build/sgx-lkl-run ./sgxlkl-miniroot-fs.img /usr/bin/redis-server --bind 10.0.1.1
```

The readme file in `apps/miniroot` contains more detailed information on how to
build custom disk images.


Debugging SGX-LKL (applications)
---------------------------------

SGX-LKL provides a wrapper around gdb. To build it, run `setup.sh` in the `gdb`
subdirectory. This will create the wrapper `sgx-lkl-gdb`. sgx-lkl-gdb
automatically loads the SGX-LKL gdb plugin which ensures that debug symbols (if
available) are loaded correctly. In addition, when running in HW mode,
sgx-lkl-gdb uses the corresponding SGX debug instructions to read from and
write to enclave memory. Example:

```
SGXLKL_TAP=sgxlkl_tap0 SGXLKL_VERBOSE=1 ../../gdb/sgx-lkl-gdb --args ../../build/sgx-lkl-run ./alpine-rootfs.img /usr/bin/redis-server --bind 10.0.1.1
```

Note: SGX-LKL should be built in debug mode for full gdb support:

```
# HW debug mode
make DEBUG=true

# Sim debug mode
make sim DEBUG=true
```

Also note that SGX-LKL does support applications that use the `CPUID` and
`RDTSC` instructions. However, since `CPUID` and `RDTSC` are not permitted
within SGX enclaves, gdb will catch resulting SIGILL signals and pause
execution by default. SGX-LKL handles these signals transparently. Continue
with `c`/`continue` or instruct gdb not to stop for `SIGILL` signals (`handle
SIGILL nostop`). Be careful though as this includes `SIGILL` signals caused by
other illegal instructions. Similarly, for applications that define their own
signal handler for `SIGSEGV` signals, gdb will pause execution. When
continuing, SGX-LKL will pass on the signal to the in-enclave signal handler
registered by the application.
