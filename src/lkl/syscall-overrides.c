#include <sys/syscall.h>
#include "lkl/syscall-overrides-fstat.h"
#include "lkl/posix-host.h"

void register_lkl_syscall_overrides()
{
    orig_fstat = lkl_replace_syscall(__lkl__NR_fstat, syscall_fstat_override);
    orig_newfstatat = lkl_replace_syscall(__lkl__NR_newfstatat,
                                          syscall_newfstatat_override);
}
