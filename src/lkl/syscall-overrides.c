#include <lkl/asm/host_ops.h>
#include "lkl/syscall-overrides-futex.h"

void register_lkl_syscall_overrides()
{
    lkl_replace_syscall(202, (void *)syscall_SYS_futex_override);
}
