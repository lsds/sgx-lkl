#ifndef _LKL_SYSCALL_OVERRIDES_SYSINFO_H
#define _LKL_SYSCALL_OVERRIDES_SYSINFO_H

/* Override lkl-provided sysinfo handler. Report enclave-specific data */
long syscall_sysinfo_override(struct sysinfo* info);

#endif