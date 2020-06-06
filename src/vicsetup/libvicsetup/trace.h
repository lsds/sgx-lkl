#ifndef _VIC_TRACE_H
#define _VIC_TRACE_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <vic.h>
#include "defs.h"

typedef enum vic_trace_level
{
    VIC_TRACE_NONE = 0,
    VIC_TRACE_FATAL = 1,
    VIC_TRACE_ERROR = 2,
    VIC_TRACE_WARNING = 3,
    VIC_TRACE_DEBUG = 4,
}
vic_trace_level_t;

void vic_trace_set_level(uint32_t level);

uint32_t vic_trace_get_level(void);

void __vic_trace_ap(
    uint32_t level,
    const char* file,
    uint32_t line,
    const char* func,
    const char* format,
    va_list ap);

VIC_INLINE void __vic_trace(
    uint32_t level,
    const char* file,
    uint32_t line,
    const char* func,
    const char* format,
    ...)
{
    va_list ap;
    va_start(ap, format);
    __vic_trace_ap(level, file, line, func, format, ap);
    va_end(ap);
}

#define TRACE \
    do \
    { \
        printf("TRACE: %s(%u): %s()\n", __FILE__, __LINE__, __FUNCTION__); \
        fflush(stdout); \
    } \
    while (0)

#endif /* _VIC_TRACE_H */
