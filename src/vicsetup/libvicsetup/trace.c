#include "trace.h"
#include <stdio.h>

static uint32_t _level;

void vic_trace_set_level(uint32_t level)
{
    _level = level;
}

uint32_t vic_trace_get_level(void)
{
    return _level;
}

void __vic_trace_ap(
    uint32_t level,
    const char* file,
    uint32_t line,
    const char* func,
    const char* format,
    va_list ap)
{
    if (level > _level)
        return;

    fprintf(stderr, "TRACE(%u): %s(%u): %s(): ", level, file, line, func);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
}
