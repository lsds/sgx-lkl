#include <stdarg.h>
#include <stdlib.h>

#include "enclave/enclave_util.h"

// Integer base 2 logarithm.
int int_log2(unsigned long long arg)
{
    int l = 0;
    while (arg >>= 1)
        l++;
    return l;
}

#ifdef DEBUG

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <enclave/lthread.h>
#include <openenclave/internal/print.h>
#include "lkl_host.h"

#define EPOLL_EVENT_FLAG_BUFFER_LEN 256

#undef __LKL_SYSCALL
#define __LKL_SYSCALL(nr) {(const char*)(__lkl__NR_##nr), #nr},
#include <lkl.h>
static const char* __lkl_syscall_names[][2] = {
#include <lkl/syscalls.h>
    {NULL, NULL},
#undef __LKL_SYSCALL
};

static void parse_epoll_event_flags(
    char* buf,
    size_t buf_len,
    struct epoll_event* evt)
{
    size_t written = 0;
    if (evt->events & EPOLLIN)
    {
        written = snprintf(buf, buf_len - written, "EPOLLIN");
        buf += written;
    }
    if (evt->events & EPOLLOUT)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLOUT", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLRDHUP)
    {
        written = snprintf(
            buf, buf_len - written, "%sEPOLLRDHUP", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLPRI)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLPRI", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLERR)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLERR", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLHUP)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLHUP", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLET)
    {
        written =
            snprintf(buf, buf_len - written, "%sEPOLLET", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLONESHOT)
    {
        written = snprintf(
            buf, buf_len - written, "%sEPOLLONESHOT", written ? "|" : "");
        buf += written;
    }
    if (evt->events & EPOLLWAKEUP)
    {
        written = snprintf(
            buf, buf_len - written, "%sEPOLLWAKEUP", written ? "|" : "");
        buf += written;
    }

    buf[0] = '\0';
}

long __sgxlkl_log_syscall(sgxlkl_syscall_kind type, long n, long res, int params_len, ...)
{
    const char* name = NULL;
    char errmsg[255] = {0};

    if (!sgxlkl_trace_ignored_syscall && type == SGXLKL_IGNORED_SYSCALL)
        return res;

    if (!sgxlkl_trace_unsupported_syscall && type == SGXLKL_UNSUPPORTED_SYSCALL)
        return res;

    if (!sgxlkl_trace_lkl_syscall && type == SGXLKL_LKL_SYSCALL)
        return res;

    if (!sgxlkl_trace_internal_syscall && type == SGXLKL_INTERNAL_SYSCALL)
        return res;

    long params[6] = {0};
    va_list valist;
    va_start(valist, params_len);
    for (int i = 0; i < params_len; i++)
    {
        params[i] = va_arg(valist, long);
    }
    va_end(valist);

    for (int i = 0; __lkl_syscall_names[i][1] != NULL; i++)
    {
        if ((long)__lkl_syscall_names[i][0] == n)
        {
            name = __lkl_syscall_names[i][1];
            break;
        }
    }

    if (name == NULL)
        name = "### INVALID ###";
    if (res < 0)
        snprintf(errmsg, sizeof(errmsg), " (%s) <--- !", lkl_strerror(res));

    int tid = lthread_self() ? lthread_self()->tid : 0;
    if (type == SGXLKL_REDIRECT_SYSCALL)
    {
        // n is x64 syscall number, name is not available.
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] \t%ld\t(%ld, %ld, %ld, %ld, %ld, %ld) = %ld%s\n",
            tid,
            n,
            params[0],
            params[1],
            params[2],
            params[3],
            params[4],
            params[5],
            res,
            errmsg);
    }
    else if (n == SYS_newfstatat)
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%ld, %s, %ld, %ld) = %ld %s\n",
            tid,
            name,
            n,
            params[0],
            (const char*)params[1],
            params[2],
            params[3],
            res,
            errmsg);
    }
    else if (n == SYS_openat)
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%ld, %s, %ld, %ld) = %ld %s\n",
            tid,
            name,
            n,
            params[0],
            (const char*)params[1],
            params[2],
            params[3],
            res,
            errmsg);
    }
    else if (n == SYS_execve)
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%s, %s, %s, %ld, %ld) = %ld %s\n",
            tid,
            name,
            n,
            (const char*)(params[0]),
            ((const char**)params[1])[0],
            ((const char**)params[1])[1],
            params[2],
            params[3],
            res,
            errmsg);
    }
    else if (n == SYS_statx)
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%ld, %s, %ld, %ld, %ld) = %ld %s\n",
            tid,
            name,
            n,
            params[0],
            (const char*)params[1],
            params[2],
            params[3],
            params[4],
            res,
            errmsg);
    }
    else if (n == SYS_epoll_ctl)
    {
        char event_flags[EPOLL_EVENT_FLAG_BUFFER_LEN];
        struct epoll_event* evt = (struct epoll_event*)params[3];
        parse_epoll_event_flags(event_flags, EPOLL_EVENT_FLAG_BUFFER_LEN, evt);
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%d, %d, %d, %p {%s}) = %ld %s\n",
            tid,
            name,
            n,
            (int)params[0],
            (int)params[1],
            (int)params[2],
            evt,
            event_flags,
            res,
            errmsg);
    }
    else if (n == SYS_epoll_pwait)
    {
        char event_flags[EPOLL_EVENT_FLAG_BUFFER_LEN];
        struct epoll_event* evt = (struct epoll_event*)params[1];
        parse_epoll_event_flags(event_flags, EPOLL_EVENT_FLAG_BUFFER_LEN, evt);
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%d, %p {%s}, %d, %d, %ld) = %ld %s\n",
            tid,
            name,
            n,
            (int)params[0],
            evt,
            event_flags,
            (int)params[2],
            (int)params[3],
            params[4],
            res,
            errmsg);
    }
    else
    {
        SGXLKL_TRACE_SYSCALL(
            type,
            "[tid=%-3d] %s\t%ld\t(%ld, %ld, %ld, %ld, %ld, %ld) = %ld%s\n",
            tid,
            name,
            n,
            params[0],
            params[1],
            params[2],
            params[3],
            params[4],
            params[5],
            res,
            errmsg);
    }
	return res;
}
#endif /* DEBUG */
