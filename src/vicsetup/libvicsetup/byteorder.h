#ifndef _VIC_BYTEORDER_H
#define _VIC_BYTEORDER_H

#include <stdbool.h>
#include <stdint.h>

#if defined(__i386) || defined(__x86_64)
#define vic_is_big_endian() false
#else
#error "unsupported"
#endif

static __inline__ uint64_t vic_swap_u64(uint64_t x)
{
    if (vic_is_big_endian())
    {
        return x;
    }
    else
    {
        return ((uint64_t)((x & 0xFF) << 56)) |
               ((uint64_t)((x & 0xFF00) << 40)) |
               ((uint64_t)((x & 0xFF0000) << 24)) |
               ((uint64_t)((x & 0xFF000000) << 8)) |
               ((uint64_t)((x & 0xFF00000000) >> 8)) |
               ((uint64_t)((x & 0xFF0000000000) >> 24)) |
               ((uint64_t)((x & 0xFF000000000000) >> 40)) |
               ((uint64_t)((x & 0xFF00000000000000) >> 56));
    }
}

static __inline__ uint32_t vic_swap_u32(uint32_t x)
{
    if (vic_is_big_endian())
    {
        return x;
    }
    else
    {
        return ((uint32_t)((x & 0x000000FF) << 24)) |
               ((uint32_t)((x & 0x0000FF00) << 8)) |
               ((uint32_t)((x & 0x00FF0000) >> 8)) |
               ((uint32_t)((x & 0xFF000000) >> 24));
    }
}

static __inline__ int16_t vic_swap_u16(int16_t x)
{
    if (vic_is_big_endian())
    {
        return x;
    }
    else
    {
        return ((int16_t)((x & 0x00FF) << 8)) | ((int16_t)((x & 0xFF00) >> 8));
    }
}

#endif /* _VIC_BYTEORDER_H */
