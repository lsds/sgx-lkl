// If both kernel and user space have references to the start and end of the
// .init_array and .fini_array sections and those sections contain a mix of
// kernel and userspace function pointers, then both can potentially run 
// constructors / destructors from the other component.
// OE and LKL don't define those sections, but if OE references them
// then OE's init routine (init_fini.c) will call libc init functions in user space.
// And then libc in user space will call them again. This would create undefined behaviour.

// OE's init routine references the symbols below that would normally be
// magically provided by the linker. 
// Since we reserve the privilege of constructors / destructors for user space
// we need to satisfy OE by providing local symbols ourselves.
// The symbols below are equivalent to not having any initializers/finalizers.
// This is done by assigning the same address to the start/end pointers.
// The kernel space object is checked with objdump to verify that it really does
// not contain any .init_array and .fini_array sections (and a few others),
// since those would otherwise be called from user space.

.hidden __init_array_start
.hidden __init_array_end
.hidden __fini_array_start
.hidden __fini_array_end
.type __init_array_start,@object
.type __init_array_end,@object
.type __fini_array_start,@object
.type __fini_array_end,@object
.globl __init_array_start
.globl __init_array_end
.globl __fini_array_start
.globl __fini_array_end
.p2align 3
__init_array_start:
__init_array_end:
__fini_array_start:
__fini_array_end:
.quad 0 # 0x0
.quad 0 # 0x0
.size __init_array_start, 16
.size __init_array_end, 16
.size __fini_array_start, 16
.size __fini_array_end, 16
