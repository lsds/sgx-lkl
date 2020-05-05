#include "lkl/syscall-overrides-futex.h"
#include "lkl/posix-host.h"

void register_lkl_syscall_overrides()
{
    lkl_replace_syscall(__lkl__NR_futex, (void *)syscall_SYS_futex_override);
}
