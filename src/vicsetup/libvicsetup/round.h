#ifndef _VIC_ROUND_H
#define _VIC_ROUND_H

#include <stdint.h>

static __inline__ uint64_t vic_round_up(uint64_t x, uint64_t m)
{
    return (x + m - 1) / m * m;
}

#endif /* _VIC_ROUND_H */
