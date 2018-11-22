[![Build Status](https://travis-ci.org/lsds/sgx-lkl.svg?branch=master)](https://travis-ci.org/lsds/sgx-lkl)

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

SGX-LKL has been tested on Ubuntu 16.04 and 18.04. To run SGX-LKL in SGX
enclaves, the Intel SGX driver (available at
https://github.com/01org/linux-sgx-driver and
https://01.org/intel-software-guard-extensions/downloads) is required. We have
tested SGX-LKL with driver versions 1.9 and 2.0. SGX-LKL also provides a
simulation mode for which no SGX-enabled CPU is needed. Furthermore the
following packages are required to build SGX-LKL:
`make`, `gcc`, `bc`, `python`, `xutils-dev` (for `makedepend`), `bison`, `flex`.

Install these with:

```
sudo apt-get install make gcc bc python xutils-dev bison flex
```

Compilation has been tested with versions 5.4 and 7.3 of gcc. Older versions might lead
to compilation and/or linking errors.

### Networking support

In order for SGX-LKL applications to send and receive packets via the network, a
TAP interface is needed on the host. Create it as follows:

```
sudo ip tuntap add dev sgxlkl_tap0 mode tap user `whoami`
sudo ip link set dev sgxlkl_tap0 up
sudo ip addr add dev sgxlkl_tap0 10.0.1.254/24
```

SGX-LKL will use the IP address `10.0.1.1` by default. To change it, set the
environment variable `SGXLKL_IP4`. The name of the TAP interface is set
using the environment variable `SGXLKL_TAP`.

The interface can be removed again by running the following command:

```
sudo ip tuntap del dev sgxlkl_tap0 mode tap
```

If you require your application to be reachable from/reach other hosts,
additional `iptable` rules to forward corresponding traffic might be needed.
For example, for redis which listens on port 6379 by default:


```
# Forward traffic from host's public interface port 60321 to SGX-LKL port 6379
sudo iptables -t nat -I PREROUTING -p tcp -d `hostname -i` --dport 60321 -j DNAT --to-destination 10.0.1.1:6379
sudo iptables -I FORWARD -m state -d 10.0.1.0/24 --state NEW,RELATED,ESTABLISHED -j ACCEPT
sudo iptables -I FORWARD -m state -s 10.0.1.0/24 --state NEW,RELATED,ESTABLISHED -j ACCEPT

sudo sysctl -w net.ipv4.ip_forward=1
```

If SGX-LKL should be allowed to access the internet or other networks,
masquerading might be needed:

```
sudo iptables -t nat -A POSTROUTING -s 10.0.1.0/24 ! -d 10.0.1.0/24 -j MASQUERADE
```

Building SGX-LKL manually
-------------------------

### Hardware mode

To build sgx-lkl in hardware mode run:

```
    make
    make sgx-lkl-sign    # this signs the SGX-LKL enclave library as a debug enclave
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
make sgx-lkl-sign
# Sim mode
make sim DEBUG=true
```


Building SGX-LKL using Docker
-----------------------------

Building SGX-LKL using Docker requires at least Docker version 17 to include
multi-stage build support. There is a script `sgx-lkl-docker.sh` to build
SGX-LKL inside a Docker container independently of the host environment:

```
./sgx-lkl-docker.sh build -s   # This builds SGX-LKL in simulation mode
```

After SGX-LKL has been built, it is possible to deploy the container with the
Java HelloWorld example on the local (or a remote) machine:

```
./sgx-lkl-docker.sh deploy-jvm-helloworld -s
```

(Deployment on a remote Docker machine requires `docker-machine` to be set up.)

A list of options can be obtained with:

```
./sgx-lkl-docker.sh -h
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
`apps/jvm/helloworld-java`. Building the example requires `curl` and a Java 8
compiler on the host system. On Ubuntu, you can install these by running

```
sudo apt-get install curl openjdk-8-jdk
```

To build the disk image, run

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
`<sgx-lkl>/tools` directory. For more complex applications, SGX-LKL or JVM
arguments might have to be adjusted, e.g. to increase the enclave size or the
size of the JVM heap/metaspace/code cache size, or to enable networking support
by providing a TAP/TUN interface via `SGXLKL_TAP`.

If the application runs successfully, you should see an output like this:

```
OpenJDK 64-Bit Server VM warning: Can't detect initial thread stack location - find_vma failed
Hello world!
```

Note: The warning is caused by the fact that the JVM is trying to receive
information about the process's virtual memory regions from `/proc/self/maps`.
While SGX-LKL generally supports the `/proc` file system in-enclave,
`/proc/self/maps` is currently not populated by SGX-LKL. This does not affect
the functionality of the JVM.

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
SGXLKL_TAP=sgxlkl_tap0 ../../../build/sgx-lkl-run ./sgxlkl-miniroot-fs.img /usr/bin/redis-server --bind 10.0.1.1
```

The readme file in `apps/miniroot` contains more detailed information on how to
build custom disk images.

### Cross-compiling applications for SGX-LKL

For applications with a complex build process and/or a larger set of
dependencies it is easiest to use the unmodified binaries from the Alpine Linux
repository as described in the previous section. However, it is also possible
to cross-compile applications on non-musl based Linux distributions (e.g.
Ubuntu) and create a minimal disk image that only contains the application and
its dependencies. An example of how to cross-compile a C application and create
the corresponding disk image can be found in `apps/helloworld`. To build the
disk image and execute the application with SGX-LKL run

```
make sgxlkl-disk.img
../../build/sgx-lkl-run sgxlkl-disk.img /app/helloworld
```

### Support for non-PIE binaries

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

By default, SGX-LKL maps the enclave at an arbitrary free space in memory. To
run a non-PIE binary and map the enclave at the beginning of the address space,
use `SGXLKL_NON_PIE=1`, e.g.:

```
    cd apps/helloworld
    SGXLKL_NON_PIE=1 ../../build/sgx-lkl-run sgxlkl-disk.img app/helloworld
```

### Configuring SGX-LKL

#### Enclave size

With SGX, the enclave size is fixed at creation/initialization time. By
default, SGX-LKL uses a heap size that will fit into the EPC (together with
SGX-LKL itself). However, for many applications this might be insufficient. In
order to increase the size of the heap, use the `SGXLKL_HEAP` parameter:

```
SGXLKL_TAP=sgxlkl_tap0 SGXLKL_HEAP=200M SGXLKL_KEY=../../../build/config/enclave_debug.key ../../../build/sgx-lkl-run ./sgxlkl-miniroot-fs.img /usr/bin/redis-server --bind 10.0.1.1

```

Whenever `SGXLKL_HEAP` is specified, it is also necessary to specify
`SGXLKL_KEY` which will be discussed in the next section.

Note that due to the limited Enclave Page Cache (EPC) size, performance might
degrade for applications with a large memory footprint due to paging between
the EPC and regular DRAM.

#### Enclave signing

Every enclave must be signed by its owner before it can be deployed. Without a
signature, it is not possible to initialize and run an SGX enclave. As seen in
the example above, a key can be specified via the `SGXLKL_KEY` parameter.
During the build process of SGX-LKL, a default 3072-bit RSA development/debug
key pair is generated. The corresponding key file is stored at
`build/config/enclave_debug.key`. This key is also used to generate a default
signature which is embedded into the SGX-LKL library and is used in case
`SGXLKL_HEAP` is not set. Anytime `SGXLKL_HEAP` is set or a custom key should
be used, `SGXLKL_KEY` must point to a valid key file. To generate a new key
(file), the `tools/gen_enclave_key.sh` script can be used:

```
tools/gen_enclave_key.sh <path-to-new-key-file>
```

#### Other configuration options

SGX-LKL has a number of other configuration options for e.g. configuring the
in-enclave scheduling, network configuration, or debugging/tracing. To see all
options, run

```
./build/sgx-lkl-run --help
```

Note that for the debugging options to have an effect, SGX-LKL must be built with `DEBUG=true`.


Debugging SGX-LKL (applications)
---------------------------------

SGX-LKL provides a wrapper around gdb. To build it, run `setup.sh` in the `gdb`
subdirectory. This will create the wrapper `sgx-lkl-gdb`. sgx-lkl-gdb
automatically loads the SGX-LKL gdb plugin which ensures that debug symbols (if
available) are loaded correctly. In addition, when running in HW mode,
sgx-lkl-gdb uses the corresponding SGX debug instructions to read from and
write to enclave memory. Example:

```
SGXLKL_TAP=sgxlkl_tap0 ../../gdb/sgx-lkl-gdb --args ../../build/sgx-lkl-run ./alpine-rootfs.img /usr/bin/redis-server --bind 10.0.1.1
```

Note: SGX-LKL should be built in debug mode for full gdb support:

```
# HW debug mode
make DEBUG=true
make sgx-lkl-sign

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

Support for profiling SGX-LKL with perf is currently limited to simulation
mode. Only SGX-LKL symbols but no symbols of the application or its
dependencies are available to perf due to the in-enclave linking/loading.
