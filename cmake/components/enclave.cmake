include_guard(GLOBAL)
include(cmake/components/kernel.cmake)
include(cmake/components/user.cmake)

# The enclave image of SGX-LKL is separated into two parts:
# 1. Kernel space
#   - Open Enclave
#   - LKL
#   - Enclave entrypoint
# 2. User space
#   - libc (musl, or later glibc)
#   - vicsetup
#   - libcurl
#   - mbedtls
#   - libdevicemapper
#   - libext2fs
#   - Linux init "process"
# Note on libc:
#   In the future we will have dynamically linked variants
#   of libc for user processes, while the init "process" and
#   its required libraries (libcurl etc.) rely on a statically linked musl.
# Note on Open Enclave:
#   Due to architectural issues we will have to include oelibc as well (oembedtls dependency).
#   Since we hide all symbols in the kernel object this will not interfere with user space.
# The only dependency from user space to kernel space is via the lkl_syscall function.
# The only dependency from kernel space to user space is via the libc entrypoint function (TODO name?).
# To enforce this separation and to allow having two copies of mbedtls we need to:
# - Partially link all kernel space objects into a single object file.
# - Partially link all user space objects into a single object file.
# - Verify no unresolved symbols exist:
#     ! nm -g libsgxlkl_kernel.o | grep ' U '
#     ! nm -g libsgxlkl_user.o | grep ' U '
# - Hide all kernel space symbols except lkl_syscall and the enclave entrypoint.
# - Hide all user space symbols except the libc entrypoint and libc itself (apps need libc).
# - Fully link both object files into an enclave image.
# `ld -r` can be used for partial linking, `objcopy --keep-global-symbol=..` for hiding symbols.

# Open Enclave treats enclave images as executables.
# Their entry point is the _start symbol.
# This symbol is provided by OE and part of the kernel object.
add_executable(sgxlkl_enclave_image
    $<TARGET_OBJECTS:sgx-lkl::kernel>
    $<TARGET_OBJECTS:sgx-lkl::user>
    )
target_link_libraries(sgxlkl_enclave_image PRIVATE 
    # libgcc provides compiler runtime symbols like __muldc3.
    # libc/musl in the user space object pulls those in.
    # Ideally we would already link against libgcc during the partial link
    # of the user object, but to do that we would need to know the compiler-specific
    # location of libgcc, which the linker (ld) does not automatically add.
    # Here we use the compiler for the final link, and it does add the right search path.
    gcc
    )
target_link_options(sgxlkl_enclave_image PRIVATE
    -nostdlib
    -nodefaultlibs
    -nostartfiles
    LINKER:--gc-sections
    LINKER:--no-undefined
    LINKER:-Bstatic
    LINKER:-Bsymbolic
    LINKER:--export-dynamic
    LINKER:-pie
    LINKER:--build-id
    LINKER:-z,noexecstack
    LINKER:-z,now
    )
set_target_properties(sgxlkl_enclave_image PROPERTIES LINKER_LANGUAGE C)
add_executable(sgx-lkl::enclave-image ALIAS sgxlkl_enclave_image)
