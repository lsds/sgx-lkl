// NOTE: THIS FILE IS NOT CURRENTLY USED!
// It was needed when linking against oeenclave.o,
// but the current CMake build links against OE's static
// archives directly which avoids pulling in unneeded functions.
// The list below is also not complete is only a subset of all
// undefined functions from oeenclave.o.

// Stubs as we currently need to link in oesyscall.
// This will disappear in the future.

void abort(void);

void oe_syscall_close_ocall(){abort();}
void oe_syscall_dup_ocall(){abort();}
void oe_syscall_epoll_wake_ocall(){abort();}
void oe_syscall_fcntl_ocall(){abort();}
void oe_syscall_getegid_ocall(){abort();}
void oe_syscall_geteuid_ocall(){abort();}
void oe_syscall_getgid_ocall(){abort();}
void oe_syscall_getgroups_ocall(){abort();}
void oe_syscall_getpgid_ocall(){abort();}
void oe_syscall_getpgrp_ocall(){abort();}
void oe_syscall_getpid_ocall(){abort();}
void oe_syscall_getppid_ocall(){abort();}
void oe_syscall_getuid_ocall(){abort();}
void oe_syscall_ioctl_ocall(){abort();}
void oe_syscall_nanosleep_ocall(){abort();}
void oe_syscall_poll_ocall(){abort();}
void oe_syscall_read_ocall(){abort();}
void oe_syscall_readv_ocall(){abort();}
void oe_syscall_uname_ocall(){abort();}
void oe_syscall_write_ocall(){abort();}
void oe_syscall_writev_ocall(){abort();}

void oe_realloc_ocall(){abort();}
void oe_sgx_thread_wake_wait_ocall(){abort();}