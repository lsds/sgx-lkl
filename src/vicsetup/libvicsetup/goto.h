#ifndef _VIC_GOTO_H
#define _VIC_GOTO_H

#include <stdint.h>
#include <stdio.h>

#include "trace.h"
#include "vic.h"

#define GOTO(LABEL)                               \
    do                                            \
    {                                             \
        __goto(__FILE__, __LINE__, __FUNCTION__); \
        fflush(stdout);                           \
        goto LABEL;                               \
    } while (0)

static __inline__ void __goto(const char* file, uint32_t line, const char* func)
{
    __vic_trace(VIC_TRACE_ERROR, file, line, func, "GOTO");
}

#endif /* _VIC_GOTO_H */
