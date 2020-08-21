#ifndef _VIC_RAISE_H
#define _VIC_RAISE_H

#include <stdint.h>
#include <stdio.h>

#include "trace.h"
#include "vic.h"

#define RAISE(RAISE)                                       \
    do                                                     \
    {                                                      \
        result = RAISE;                                    \
        __raise(__FILE__, __LINE__, __FUNCTION__, result); \
        fflush(stdout);                                    \
        goto done;                                         \
    } while (0)

#define CHECK(RAISE)                                           \
    do                                                         \
    {                                                          \
        vic_result_t _r_ = RAISE;                              \
        if (_r_ != VIC_OK)                                     \
        {                                                      \
            result = _r_;                                      \
            __raise(__FILE__, __LINE__, __FUNCTION__, result); \
            goto done;                                         \
        }                                                      \
    } while (0)

static __inline__ void __raise(
    const char* file,
    uint32_t line,
    const char* func,
    vic_result_t result)
{
    __vic_trace(
        VIC_TRACE_ERROR,
        file,
        line,
        func,
        "RAISE: result=%u: %s",
        result,
        vic_result_string(result));
}

#endif /* _VIC_RAISE_H */
