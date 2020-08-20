libsgxlkl-user.so
=================

This directory builds **libsgxlkl-user.so**: the user-space image that hosts
the C runtime (crt), which contains the dynamic program loader (ldso) and the
the C library (libc).

SGX-LKL builds two ELF images that are loaded into the enclave.

    - libsgxlkl.so (the kernel-space image)
    - libsgxlkl-user.so (the user-space image)

Both are passed to the Open Enclave **create_enclave()** function in the
**path** argument, which has the form:

    "<enclave-elf>:<extra-elf>"

For example:

    "libsgxlkl.so:libsgxlkl-user.so"

Open Enclave loads the two images into distinct ELF memory regions. This
effectively isolates the symbols of the two images. The kernel enters the
user-space image through its entry point given by its ELF header, passing
state information and callbacks (through a C structure). The user-space
image calls back into the kernel via these callbacks.

The main functions of the user-space image are to

    - Initialize the C library
    - Load the application program and any shared libraries
    - Start executing the application program

During its execution, the program calls C library functions that may initiate
syscalls. These syscalls are forwarded to the kernel-space image for handling.

This directory provides the following sources:

    - userargs.h - defines the struct passed by the kernel to the entry point.
    - enter.c - contains the entry point (**sgxlkl_user_enter()**).
    - stubs.c - contains stubs that invoke callback functions.

