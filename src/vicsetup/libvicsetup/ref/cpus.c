#include "cpus.h"

#include <unistd.h>

#if 0
uint64_t vic_num_cpus(void)
{
    int n = sysconf(_SC_NPROCESSORS_ONLN);

    if (n <= 0)
        return (uint64_t)-1;

    return (uint64_t)n;
}
#endif
