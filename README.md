SGX-LKL-OE (Open Enclave Edition)
=================================



*WARNING:* This branch contains an experimental port of SGX-LKL to use Open Enclave as an enclave abstraction layer.
This is an ongoing research project.
Various features are under development and there are several known bugs.

[![Build Status](https://dev.azure.com/sgx-lkl/sgx-lkl/_apis/build/status/sgx-lkl?branchName=oe_port)](https://dev.azure.com/sgx-lkl/sgx-lkl/_build/latest?definitionId=1&branchName=oe_port)

The SGX-LKL project is designed to run existing unmodified Linux binaries inside of Intel SGX enclaves. The goal of the project is to provide the necessary system support for complex applications (e.g., TensorFlow, PyTorch, and OpenVINO) and programming language runtimes (e.g., Python, the DotNet CLR and the JVM). SGX-LKL can run these applications in SGX enclaves without modifications or reliance on the untrusted host OS.
Known incompatibilities are documented in [Incompatibilities.md](docs/Incompatibilities.md).

The SGX-LKL project includes several components:

 - A launcher and host interface modelled after a lightweight VM interface.
   This is documented in [HostInterface.md](docs/HostInterface.md).
 - A port of Linux to run in this environment, using the Linux Kernel Library (LKL) (https://github.com/lkl/linux).
 - A port of the musl standard C library to run on top of this version of Linux.

For frequently asked questions, please see the [FAQ](docs/FAQ.md).

SGX-LKL uses the Linux Kernel Library (LKL) (https://github.com/lkl/linux)
to provide a mature POSIX implementation within an enclave. A modified version 
of the musl standard C library (https://www.musl-libc.org) is available to 
applications inside the enclave.

SGX-LKL supports in-enclave user-level threading, signal handling, and file
and network I/O. System calls are handled within the enclave by LKL, and the 
host is used only for access to I/O resources.

SGX-LKL can be run in hardware mode, when it requires an Intel SGX compatible
CPU, and also in software simulation mode, when it runs on any Intel CPU
without hardware security guarantees. 

A. Installing SGX-LKL-OE
------------------------

SGX-LKL-OE is distributed as Debian package.
This package is alpha quality and not meant for production.

The SGX-LKL-OE package contains the runtime, tools, and all its dependencies
and can be run on any Linux distribution.

To use development releases (updated on every commit to `master`), run:
```sh
echo "deb [trusted=yes] https://clcpackages.blob.core.windows.net/apt-dev/1fa5fb889b8efa6ea07354c3b54903f7 ./" | sudo tee /etc/apt/sources.list.d/azure-clc.list
```

To use stable releases (manually published), run:
```sh
echo "deb [trusted=yes] https://clcpackages.blob.core.windows.net/apt/1fa5fb889b8efa6ea07354c3b54903f7 ./" | sudo tee /etc/apt/sources.list.d/azure-clc.list
```

Now, install with:
```sh
sudo apt update
# or: sgx-lkl-nonrelease (-release variant will follow)
sudo apt install sgx-lkl-debug
```

To make the SGX-LKL commands available from any directory, add an entry to 
the `PATH` environment variable:
```
PATH="$PATH:/opt/sgx-lkl/bin"
```

Finally, setup the host environment by running:
```
sgx-lkl-setup
```

SGX-LKL works most performant with a Linux kernel that has support for userspace FSGSBASE instructions. Otherwise, support for thread local storage (TLS) must use emulated instructions, which reduces performance.
SGX-LKL outputs a message on start-up if the currently running Linux kernel does not support FSGSBASE instructions.

FSGSBASE support is not part of the mainline Linux kernel yet.
Azure VMs run on Linux kernels [with FSGSBASE support](https://bugs.launchpad.net/ubuntu/+source/linux-azure/+bug/1877425) based on a proposed Linux kernel patch.
To apply the latest patch version to non-Azure systems you may follow the instructions [here](tools/ubuntu-patched-kernel-fsgsbase).

B. Building SGX-LKL-OE from source
----------------------------------

SGX-LKL has been tested on Ubuntu Linux 18.04 and with a gcc compiler
version of 7.4 or above. Older compiler versions may lead to compilation
and/or linking errors.

1. Install the SGX-LKL build dependencies:
```
sudo apt-get install make gcc g++ bc python xutils-dev bison flex libgcrypt20-dev libjson-c-dev automake autopoint autoconf pkgconf libtool libcurl4-openssl-dev libprotobuf-dev libprotobuf-c-dev protobuf-compiler protobuf-c-compiler libssl-dev
```

2. Clone the SGX-LKL git repository:
```
git clone --branch oe_port --recursive https://github.com/lsds/sgx-lkl.git
cd sgx-lkl
```

3. Install the Open Enclave build dependencies:
```
cd openenclave
sudo scripts/ansible/install-ansible.sh
sudo ansible-playbook scripts/ansible/oe-contributors-setup.yml
```

Note that the above also installs the Intel SGX driver on the host.

If running on an Azure Confidential Computing (ACC) VM, which offers SGX support,
the last line above should be replaced by:
```
sudo ansible-playbook scripts/ansible/oe-contributors-acc-setup-no-driver.yml
```

4. Build SGX-LKL in the source tree:

#### DEBUG build (with debug functionality, no compiler optimisations)

To build SGX-LKL with debug symbols and without compiler optimisations, run the following 
command in the SGX-LKL source tree
```
make DEBUG=true
```
Note that, on the first invocation, this initialises all git submodules, 
including a clone of the LKL library, which downloads several GBs of data.

You will then find the build files under `build/`.

#### NON-RELEASE build (no debug symbols, with compiler optimisations)

To build SGX-LKL with compiler optimisations and without debug symbols, run:
```
make
```

#### RELEASE build _(not yet supported by SGX-LKL-OE)_

SGX-LKL has a RELEASE build, which make the resulting enclave library secure by
removing any insecure debug funcationlity and enforcing security features such
as attestestation. 

To build SGX-LKL in release mode, run:
```
    make RELEASE=true
```

5. To install SGX-LKL on the host system, use the following command:
```
sudo -E make install
```

SGX-LKL is installed under `/opt/sgx-lkl` by default. To change the install prefix, 
use `PREFIX`, e.g.:
```
make install PREFIX="${PWD}/install"
```

To uninstall SGX-LKL, run
```
sudo make uninstall
```

This removes SGX-LKL specific artefacts from the installation directory as
well as cached artefacts of `sgx-lkl-disk` (stored in `~/.cache/sgxlkl`).

6. To make the SGX-LKL commands available from any directory, add an entry to 
the `PATH` environment variable:
```
PATH="$PATH:/opt/sgx-lkl/bin"
```

7. Finally, setup the host environment by running:
```
sgx-lkl-setup
```

This has to be done after each reboot. It configures the host networking to 
forward packets from SGX-LKL instances.

C. Running applications with SGX-LKL
------------------------------------

To run applications with SGX-LKL, they must be provided as part of a 
Linux disk image. Since SGX-LKL is built using the musl libc library, 
applications must have been dynamically linked against musl. Currently, 
applications linked against glibc are not supported by SGX-LKL. The 
simplest way to run applications with SGX-LKL is to use prebuilt binaries 
for Alpine Linux, which uses musl libc as its default C standard library.

### 1. Running existing sample applications

The SGX-LKL source tree contains sample applications under 'samples/'. Most 
sample applications can be run in hardware SGX mode by going to the 
corresponding directory and execute the following command:
```
make run-hw
```

To run an application in software mode without SGX support, execute:
```
make run-sw
```

### 2. Creating SGX-LKL disk images with sgx-lkl-disk

While it is possible to create disk images manually, SGX-LKL comes with 
a helper tool `sgx-lkl-disk`. It can be used to create, check, mount, and 
unmount SGX-LKL disk images.

To see all options, run:
```
sgx-lkl-disk --help
```

The tool has been tested on Ubuntu 18.04. `sgx-lkl-disk` will need superuser 
rights for some operations, e.g. temporarily mounting/unmounting disk images.

#### Creating Alpine-based disk images

To create a disk image, use the `create` action, which expects the disk image 
size to be specified via `--size=<SIZE>` and the disk
image file name. It also requies the the source of the image.

To build an image with one or more applications available in the
Alpine package repository, use the `--alpine=<pkgs>` flag. The following example
creates an image with Redis installed:
```
sgx-lkl-disk create --size=50M --alpine="redis" sgxlkl-disk.img
```

Redis can then be run as follows:
```
SGXLKL_TAP=sgxlkl_tap0 sgx-lkl-run-oe --hw-debug ./sgxlkl-disk.img /usr/bin/redis-server --bind 10.0.1.1
```

To create and run a disk image with Memcached, execute:
```
sgx-lkl-disk create --size=50M --alpine="memcached" sgxlkl-disk.img
SGXLKL_TAP=sgxlkl_tap0 sgx-lkl-run-oe --hw-debug ./sgxlkl-disk.img /usr/bin/memcached --listen=10.0.1.1 -u root --extended=no_drop_privileges -vv
```

If you need to add extra data to the disk image, the parameter `--copy=<path>` can 
be used to copy files from the host to the disk image. The following example creates a disk 
image with the Alpine Python package together with a custom Python application:
```
# When --copy points to a directory, the contents of the directory are copied
# to the root of the file system.
tree my-python-root
> my-python-root
> ├── app
> │   ├── myapp.py
> │   └── util.py

sgx-lkl-disk create --size=100M --alpine="python" --copy=./my-python-root sgxlkl-disk.img
# Run with
sgx-lkl-run-oe --hw-debug ./sgxlkl-disk.img /usr/bin/python /app/myapp.py
```

#### Creating Docker-based disk images

The `sgx-lkl-disk` tool can also build disk images from Dockerfiles with the `--docker`
flag, e.g. when an application needs to be compiled manually. Note that SGX-LKL 
applications still need to be linked against musl libc, so a good starting 
point is an Alpine Docker base image.

To build an SGX-LKL disk image from a Dockerfile, run:
```
sgx-lkl-disk create --size=100M --docker=MyDockerfile sgxlkl-disk.img
```

#### Creating plain disk images

If all that is needed is a plain disk image based on files existing on the
host, the `--copy` flag can be used on its own:
```
sgx-lkl-disk create --size=50M --copy=./my-root sgxlkl-disk.img
```

#### Disk encryption

SGX-LKL supports disk encryption via the *dm-crypt* subsystem in the Linux
kernel. Typically encryption for a disk can be setup via the `cryptsetup` tool.
The `sgx-lkl-disk` tool provides an `--encrypt` option to simplify this 
process. To create an encrypted disk image with default options run:
```
sgx-lkl-disk create --size=50M --encrypt --key-file --alpine="" sgxlkl-disk.img.enc
# Run with
SGXLKL_HD_KEY=./sgxlkl-disk.img.enc.key sgx-lkl-run-oe --hw-debug ./sgxlkl-disk.img.enc /bin/echo "Hello World"
```

In this example, `sgx-lkl-disk` automatically generates a 512-byte key file,
uses "AES-XTS Plain 64" as a cipher/mode and "SHA256" for hashing. The cipher
and hash algorithm is stored as metadata in a LUKS header on disk.
The tool provides a number of options to customise this (see
`sgx-lkl-disk --help` for more information).

#### Disk integrity protection

To provide disk/data integrity, SGX-LKL supports both *dm-verity* (read-only) 
and *dm-integrity* (read/write). These can be combined with disk
encryption (*dm-integrity* can currently only be used together with `--encrypt`).

To create a read-only encrypted disk image with integrity
protection via *dm-verity*, run:
```
sgx-lkl-disk create --size=50M --encrypt --key-file --verity --alpine="" sgxlkl-disk.img.enc.vrt
# Run with
SGXLKL_HD_VERITY=./sgxlkl-disk.img.enc.vrt.roothash SGXLKL_HD_KEY=./sgxlkl-disk.img.enc.vrt.key sgx-lkl-run-oe ./sgxlkl-disk.img.enc.vrt /bin/echo "Hello World"
```

To create an encrypted and integrity-protected disk that uses HMAC-SHA256 for
authenticated encryption and supports both reads and writes, run:
```
# --integrity requires a host kernel version 4.12 or greater and cryptsetup version 2.0.0 or greater
sgx-lkl-disk create --size=50M --encrypt --key-file --integrity --alpine="" sgxlkl-disk.img.enc.int
# Run with
SGXLKL_HD_KEY=./sgxlkl-disk.img.enc.int.key sgx-lkl-run-oe ./sgxlkl-disk.img.enc.int /bin/echo "Hello World"
```

`sgx-lkl-disk` relies on `cryptsetup` for setting up encryption and integrity
protection. For more information on cryptsetup and 
dm-crypt/dm-verity/dm-integrity, see
https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt.

### 3. Running applications from the Alpine Linux repository

Alpine Linux uses musl as its standard C library. SGX-LKL supports a large
number of unmodified binaries available through the Alpine Linux repository.
For an example on how to create the corresponding disk image and how to run the
application, `samples/miniroot` can be used as a template. 

Build the disk image by running: 
```
make
```

This creates an Alpine mini root disk image that can be passed to `sgx-lkl-run-oe`.
`buildenv.sh` can be modified to specify APKs that should be part of the disk
image. After creating the disk image, applications can be run on top of SGX-LKL
using `sgx-lkl-run-oe`. Using Redis as an example (the APK `redis` is listed in
the example `buildenv.sh` file in `samples/miniroot`), `redis-server` can be
launched as follows:
```
SGXLKL_TAP=sgxlkl_tap0 sgx-lkl-run-oe --hw-debug ./sgxlkl-miniroot-fs.img /usr/bin/redis-server --bind 10.0.1.1
```

The readme file in `samples/miniroot` contains more detailed information on how to
build custom disk images manually.

### 4. OpenJDK Java Virtual Machine (JVM)

A simple Java HelloWorld example application is available in
`samples/jvm/helloworld-java`. Building the example requires `curl` and a Java 8
compiler on the host system. On Ubuntu, install these by running:
```
sudo apt-get install curl openjdk-8-jdk
```

To build the disk image, run:
```
cd samples/jvm/helloworld-java
make
```

This compiles the HelloWorld Java example, create a disk image with an
Alpine mini root environment, add a JVM, and add the `HelloWorld.class` file.

To run the HelloWorld java program on top of SGX-LKL inside an enclave, run"
```
sgx-lkl-java ./sgxlkl-java-fs.img HelloWorld
```

The command `sgx-lkl-java` is a simple wrapper around `sgx-lkl-run-oe`, which 
sets some common JVM arguments in order to reduce its memory footprint. It 
can be found in the `tools/` directory. For more complex applications, SGX-LKL 
or JVM arguments may have to be adjusted, e.g. to increase the size of the 
JVM heap/metaspace/code cache, or to enable networking support by providing 
a TAP/TUN interface via `SGXLKL_TAP`.

If the application runs successfully, you should see an output like this:

```
OpenJDK 64-Bit Server VM warning: Can't detect initial thread stack location - find_vma failed
Hello world!
```

The warning is caused by the fact that the JVM is trying to receive
information about the process's virtual memory regions from `/proc/self/maps`.
While SGX-LKL generally supports the `/proc` file system in-enclave,
`/proc/self/maps` is currently not populated by SGX-LKL. This does not affect
the functionality of the JVM.

### 5. Cross-compiling applications for SGX-LKL

For applications with a complex build process and/or a larger set of
dependencies, it is easiest to use the unmodified binaries from the Alpine Linux
repository as described in the previous section. However, it is also possible
to cross-compile applications on non-musl based Linux distributions (e.g.
Ubuntu) and create a minimal disk image that only contains the application and
its dependencies. An example of how to cross-compile a C application and create
the corresponding disk image can be found in `samples/helloworld`. To build the
disk image and execute the application with SGX-LKL run:
```
make sgxlkl-disk.img
sgx-lkl-run-oe --hw-debug sgxlkl-disk.img /app/helloworld
```

Run the following command in `samples/miniroot` to see a number of other
applications you should be able to execute. Keep in mind that SGX-LKL currently 
does not support the `fork()` system call, so multi-process applications will not work.

```
sgx-lkl-run-oe --hw-debug ./sgxlkl-miniroot-fs.img /bin/ls /usr/bin
```

E. Configuring SGX-LKL-OE parameters
------------------------------------

### 1. Enclave size

_To be added_

### 2. Enclave signing

_To be added_

### 3. Other configuration options

SGX-LKL-OE has a number of other configuration options e.g. for configuring the
in-enclave scheduling, network configuration, or debugging/tracing. To see all
options, run:
```
sgx-lkl-run-oe --help
```

Note that for the debugging options to have an effect, SGX-LKL must be built
with `DEBUG=true`.

F. Remote attestation
---------------------

_To be added_

G. Debugging SGX-LKL-OE and applications
-----------------------------------------

See the [Debugging](docs/Debugging.md) page for details.
