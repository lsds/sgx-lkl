#include <sys/syscall.h>
#include "lkl/syscall-overrides-fstat.h"
#include "lkl/posix-host.h"

void register_lkl_syscall_overrides()
{
    syscall_register_fstat_overrides();
}
