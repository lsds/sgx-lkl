/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#ifndef _SGXLKL_DEBUG_INCLUDE
#define _SGXLKL_DEBUG_INCLUDE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>

#include "lkl_host.h"

#define SGXLKL_LKL_SYSCALL      1
#define SGXLKL_INTERNAL_SYSCALL 3

#if DEBUG

extern int sgxlkl_verbose;
extern int sgxlkl_trace_thread;
extern int sgxlkl_trace_mmap;
extern int sgxlkl_trace_lkl_syscall;
extern int sgxlkl_trace_internal_syscall;

#define SGXLKL_VERBOSE(x, ...) if (sgxlkl_verbose) {sgxlkl_debug_printf("[    SGX-LKL   ] " x, ##__VA_ARGS__);}
#define SGXLKL_TRACE_THREAD(x, ...) if (sgxlkl_trace_thread) {sgxlkl_debug_printf("[    THREAD    ] " x, ##__VA_ARGS__);}
#define SGXLKL_TRACE_MMAP(x, ...) if (sgxlkl_trace_mmap) {sgxlkl_debug_printf("[     MMAP     ] " x, ##__VA_ARGS__);}
#define SGXLKL_TRACE_SYSCALL(type, x, ...) if ((sgxlkl_trace_lkl_syscall &&  type == SGXLKL_LKL_SYSCALL) || (sgxlkl_trace_internal_syscall &&  type == SGXLKL_INTERNAL_SYSCALL)) { \
                                                        sgxlkl_debug_printf(type == SGXLKL_LKL_SYSCALL ? "[  LKL SYSCALL ] " x : \
                                                                            "[INTRNL SYSCALL] " x, ##__VA_ARGS__);}

#define LKL_STDERR_FILENO 2
#define DEBUG_TRACE_BUF_SIZE 512

static int sgxlkl_debug_vprintf(const char *fmt, va_list args) {
    static char buf[DEBUG_TRACE_BUF_SIZE];
    int n;
    char *buffer;
    va_list copy;

    va_copy(copy, args);
    n = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);

    if (n < DEBUG_TRACE_BUF_SIZE) {
        buffer = (char*) &buf;
    } else {
        buffer = malloc(n + 1);
    }

    if (!buffer)
        return -1;

    vsnprintf(buffer, n + 1, fmt, args);

    size_t curr_index = 0;
    while (curr_index < n) {
        curr_index += write(LKL_STDERR_FILENO, buffer + curr_index, n - curr_index);
    }

    if (buffer != (char*) &buf) {
        free(buffer);
    }
    return n;
}

static int sgxlkl_debug_printf(const char *fmt, ...) {
    int n;
    va_list args;

    va_start(args, fmt);
    n = sgxlkl_debug_vprintf(fmt, args);
    va_end(args);
    return n;
}

#else

#define SGXLKL_VERBOSE(x, ...)
#define SGXLKL_TRACE_THREAD(x, ...)
#define SGXLKL_TRACE_MMAP(x, ...)
#define SGXLKL_TRACE_SYSCALL(x, ...)

#endif /* DEBUG */

#endif /* _SGXLKL_DEBUG_INCLUDE*/
