#ifndef _VIC_ERAISE_H
#define _VIC_ERAISE_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <vic.h>
#include "trace.h"

#define ERAISE(ERRNUM)                                   \
    do                                                   \
    {                                                    \
        ret = -ERRNUM;                                   \
        __eraise(__FILE__, __LINE__, __FUNCTION__, ret); \
        fflush(stdout);                                  \
        goto done;                                       \
    }                                                    \
    while (0)

#define ECHECK(ERRNUM)                                       \
    do                                                       \
    {                                                        \
        int _r_ = -ERRNUM;                                   \
        if (_r_ != VIC_OK)                                   \
        {                                                    \
            ret = _r_;                                       \
            __eraise(__FILE__, __LINE__, __FUNCTION__, ret); \
            goto done;                                       \
        }                                                    \
    }                                                        \
    while (0)

static __inline__ void __eraise(
    const char* file,
    uint32_t line,
    const char* func,
    int errnum)
{
    __vic_trace(
        VIC_TRACE_ERROR,
        file,
        line,
        func,
        "ERAISE: errno=%d: %s",
        errnum < 0 ? -errnum : errnum,
        strerror(errnum));
}

#endif /* _VIC_ERAISE_H */
