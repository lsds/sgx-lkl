#include <sys/syscall.h>
#include "lkl/syscall-overrides-fstat.h"
#include "lkl/posix-host.h"
#include "enclave/enclave_mem.h"

void register_lkl_syscall_overrides()
{
    syscall_register_fstat_overrides();
    lkl_replace_syscall(SYS_sysinfo, syscall_SYS_sysinfo);
}
