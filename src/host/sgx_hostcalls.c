/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * Copyright 2016, 2017 TU Dresden (under SCONE source code license)
 */

#define WANT_REAL_ARCH_SYSCALLS
#include "ksigaction.h"
#include "sgx_hostcalls.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "atomic.h"
#include "sgx_hostcall_interface.h"

int host_syscall_SYS_close(int fd) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    sc->syscallno = SYS_close;
    sc->arg1 = (uintptr_t)fd;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_fcntl(int fd, intptr_t cmd, intptr_t arg) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len = 0;
    void *val= 0;
    if (cmd == F_OFD_SETLK) { len = 1*sizeof(struct flock);}
    if (cmd == F_SETOWN_EX) { len = 1*sizeof(struct f_owner_ex);}
    if (cmd == F_OFD_GETLK) { len = 1*sizeof(struct flock);}
    if (cmd == F_GETOWN_EX) { len = 1*sizeof(struct f_owner_ex);}
    if (cmd == F_SETLKW) { len = 1*sizeof(struct flock);}
    if (cmd == F_OFD_SETLKW) { len = 1*sizeof(struct flock);}
    if (cmd == F_GETLK) { len = 1*sizeof(struct flock);}
    if (cmd == F_GETOWNER_UIDS) { len = 2*sizeof(uid_t);}
    if (cmd == F_SETLK) { len = 1*sizeof(struct flock);}
    if (len > 0) sc = arena_ensure(a, len, (syscall_t*) sc);
    sc->syscallno = SYS_fcntl;
    sc->arg1 = (uintptr_t)fd;
    sc->arg2 = (uintptr_t)cmd;
    if (len == 0) { sc->arg3 = (uintptr_t)arg; }
    else {val = arena_alloc(a, len); if (arg != 0) memcpy(val, (void*)arg, len); sc->arg3 = (uintptr_t)val;}
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (ssize_t)sc->ret_val;
    if (len > 0 && arg != 0) {memcpy((void*)arg, val, len);}
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_fstat(int fd, struct stat *buf) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = sizeof(*buf);
    sc = arena_ensure(a, len2, (syscall_t*) sc);
    sc->syscallno = SYS_fstat;
    sc->arg1 = (uintptr_t)fd;
    struct stat * val2;
    val2 = arena_alloc(a, len2);
    sc->arg2 = (uintptr_t)val2;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (val2 != NULL && buf != NULL) memcpy(buf, val2, len2);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_poll(struct pollfd * fds, nfds_t nfds, int timeout) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len1;
    len1 = sizeof(*fds) * nfds;
    sc = arena_ensure(a, len1, (syscall_t*) sc);
    sc->syscallno = SYS_poll;
    struct pollfd * val1;
    val1 = arena_alloc(a, len1);
    if (fds != NULL && val1 != NULL) memcpy(val1, fds, len1);
    sc->arg1 = (uintptr_t)val1;
    sc->arg2 = (uintptr_t)nfds;
    sc->arg3 = (uintptr_t)timeout;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (val1 != NULL && fds != NULL) memcpy(fds, val1, len1);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_fdatasync(int fd) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    sc->syscallno = SYS_fdatasync;
    sc->arg1 = (uintptr_t)fd;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_ioctl(int fd, unsigned long request, void * arg) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    void* val3 = arg;
    size_t len3 = 0;
    switch (request) {
        case SIOCGIFNAME:
        case SIOCGIFINDEX:
        case SIOCGIFFLAGS:
        case SIOCSIFFLAGS:
        case SIOCGIFPFLAGS:
        case SIOCSIFPFLAGS:
        case SIOCGIFADDR:
        case SIOCSIFADDR:
        case SIOCGIFDSTADDR:
        case SIOCSIFDSTADDR:
        case SIOCGIFBRDADDR:
        case SIOCSIFBRDADDR:
        case SIOCGIFNETMASK:
        case SIOCSIFNETMASK:
        case SIOCGIFMETRIC:
        case SIOCSIFMETRIC:
        case SIOCGIFMTU:
        case SIOCSIFMTU:
        case SIOCGIFHWADDR:
        case SIOCSIFHWADDR:
        case SIOCSIFHWBROADCAST:
        case SIOCGIFMAP:
        case SIOCSIFMAP:
        case SIOCADDMULTI:
        case SIOCDELMULTI:
        case SIOCGIFTXQLEN:
        case SIOCSIFTXQLEN:
        case SIOCSIFNAME:
            len3 = sizeof(struct ifreq);
    }
    sc = getsyscallslot(&a);
    if (len3 != 0) {
        sc = arena_ensure(a, len3, (syscall_t*) sc);
        val3 = arena_alloc(a, len3);
        if (val3 != NULL && arg != NULL) memcpy(val3, arg, len3);
    }
    sc->syscallno = SYS_ioctl;
    sc->arg1 = (uintptr_t)fd;
    sc->arg2 = (uintptr_t)request;
    sc->arg3 = (uintptr_t)val3;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (len3!= 0 && val3 != NULL && arg != NULL) memcpy(arg, val3, len3);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_pipe(int pipefd[2]) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len1;
    len1 = sizeof(*pipefd) * 2;
    sc = arena_ensure(a, len1, (syscall_t*) sc);
    sc->syscallno = SYS_pipe;
    int * val1;
    val1 = arena_alloc(a, len1);
    sc->arg1 = (uintptr_t)val1;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (val1 != NULL && pipefd != NULL) memcpy(pipefd, val1, len1);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

ssize_t host_syscall_SYS_pread64(int fd, void * buf, size_t count, off_t offset) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = count;
    sc = arena_ensure(a, len2, (syscall_t*) sc);
    sc->syscallno = SYS_pread64;
    sc->arg1 = (uintptr_t)fd;
    void * val2;
    val2 = arena_alloc(a, len2);
    sc->arg2 = (uintptr_t)val2;
    sc->arg3 = (uintptr_t)count;
    sc->arg4 = (uintptr_t)offset;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (ssize_t)sc->ret_val;
    if (val2 != NULL && buf != NULL) memcpy(buf, val2, len2);
    arena_free(a);
    sc->status = 0;
    return (ssize_t)__syscall_return_value;
}

ssize_t host_syscall_SYS_pwrite64(int fd, const void * buf, size_t count, off_t offset) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = count;
    sc = arena_ensure(a, len2, (syscall_t*) sc);
    sc->syscallno = SYS_pwrite64;
    sc->arg1 = (uintptr_t)fd;
    void * val2;
    val2 = arena_alloc(a, len2);
    if (buf != NULL && val2 != NULL) memcpy(val2, buf, len2);
    sc->arg2 = (uintptr_t)val2;
    sc->arg3 = (uintptr_t)count;
    sc->arg4 = (uintptr_t)offset;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (ssize_t)sc->ret_val;
    arena_free(a);
    sc->status = 0;
    return (ssize_t)__syscall_return_value;
}

ssize_t host_syscall_SYS_read(int fd, void * buf, size_t count) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = count;
    sc = arena_ensure(a, len2, (syscall_t*) sc);
    sc->syscallno = SYS_read;
    sc->arg1 = (uintptr_t)fd;
    void * val2;
    val2 = arena_alloc(a, len2);
    sc->arg2 = (uintptr_t)val2;
    sc->arg3 = (uintptr_t)count;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (ssize_t)sc->ret_val;
    if (val2 != NULL && buf != NULL) memcpy(buf, val2, len2);
    arena_free(a);
    sc->status = 0;
    return (ssize_t)__syscall_return_value;
}

ssize_t host_syscall_SYS_readv(int fd, struct iovec * iov, int iovcnt) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = 0;
    for(size_t i = 0; i < iovcnt; i++) {len2 += deepsizeiovec(&iov[i]);}
    sc = arena_ensure(a, len2, (syscall_t*) sc);
    sc->syscallno = SYS_readv;
    sc->arg1 = (uintptr_t)fd;
    struct iovec * val2;
    val2 = arena_alloc(a, sizeof(*iov) * iovcnt);
    for(size_t i = 0; i < iovcnt; i++) {deepinitiovec(a, &val2[i], &iov[i]);}
    sc->arg2 = (uintptr_t)val2;
    sc->arg3 = (uintptr_t)iovcnt;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (ssize_t)sc->ret_val;
    for(size_t i = 0; i < iovcnt; i++) {deepcopyiovec(&iov[i], &val2[i]);}
    arena_free(a);
    sc->status = 0;
    return (ssize_t)__syscall_return_value;
}

ssize_t host_syscall_SYS_write(int fd, const void * buf, size_t count) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = count;
    sc = arena_ensure(a, len2, (syscall_t*) sc);
    sc->syscallno = SYS_write;
    sc->arg1 = (uintptr_t)fd;
    void * val2;
    val2 = arena_alloc(a, len2);
    if (buf != NULL && val2 != NULL) memcpy(val2, buf, len2);
    sc->arg2 = (uintptr_t)val2;
    sc->arg3 = (uintptr_t)count;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (ssize_t)sc->ret_val;
    arena_free(a);
    sc->status = 0;
    return (ssize_t)__syscall_return_value;
}

ssize_t host_syscall_SYS_writev(int fd, const struct iovec * iov, int iovcnt) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = 0;
    for(size_t i = 0; i < iovcnt; i++) {len2 += deepsizeiovec(&iov[i]);}
    sc = arena_ensure(a, len2, (syscall_t*) sc);
    sc->syscallno = SYS_writev;
    sc->arg1 = (uintptr_t)fd;
    struct iovec * val2;
    val2 = arena_alloc(a, sizeof(*iov) * iovcnt);
    for(size_t i = 0; i < iovcnt; i++) {deepinitiovec(a, &val2[i], &iov[i]);}
    for(size_t i = 0; i < iovcnt; i++) {deepcopyiovec(&val2[i], &iov[i]);}
    sc->arg2 = (uintptr_t)val2;
    sc->arg3 = (uintptr_t)iovcnt;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (ssize_t)sc->ret_val;
    arena_free(a);
    sc->status = 0;
    return (ssize_t)__syscall_return_value;
}

int host_syscall_SYS_mprotect(void * addr, size_t len, int prot) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;

    sc = getsyscallslot(&a);
    if(!(sc && a))
        return 0;
    sc->syscallno = SYS_mprotect;

    sc->arg1 = (uintptr_t)addr;
    sc->arg2 = (uintptr_t)len;
    sc->arg3 = (uintptr_t)prot;

    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_rt_sigaction(int signum, struct sigaction * act, struct sigaction * oldact, unsigned long nsig) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = sizeof(k_sigaction_t);
    size_t len3;
    len3 = sizeof(k_sigaction_t);
    sc = arena_ensure(a, len2 + len3, (syscall_t*) sc);
    sc->syscallno = SYS_rt_sigaction;
    sc->arg1 = (uintptr_t)signum;
    struct sigaction * val2;
    val2 = arena_alloc(a, len2);
    if (act != NULL && val2 != NULL)
    {
        memcpy(val2, act, len2);
        sc->arg2 = (uintptr_t)val2;
    } else {
        sc->arg2 = (uintptr_t)NULL;
    }
    struct sigaction * val3;
    val3 = arena_alloc(a, len3);
    sc->arg3 = (uintptr_t)val3;
    sc->arg4 = (uintptr_t)nsig;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (val3 != NULL && oldact != NULL) memcpy(oldact, val3, len3);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_rt_sigpending(sigset_t * set, unsigned long nsig) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len1;
    len1 = sizeof(*set);
    sc = arena_ensure(a, len1, (syscall_t*) sc);
    sc->syscallno = SYS_rt_sigpending;
    sigset_t * val1;
    val1 = arena_alloc(a, len1);
    sc->arg1 = (uintptr_t)val1;
    sc->arg2 = (uintptr_t)nsig;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (val1 != NULL && set != NULL) memcpy(set, val1, len1);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_rt_sigprocmask(int how, void * set, sigset_t * oldset, unsigned long nsig) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = sizeof(sigset_t);
    size_t len3;
    len3 = sizeof(sigset_t);
    sc = arena_ensure(a, len2 + len3, (syscall_t*) sc);
    sc->syscallno = SYS_rt_sigprocmask;
    sc->arg1 = (uintptr_t)how;
    void * val2;
    val2 = arena_alloc(a, len2);
    if (set != NULL && val2 != NULL) memcpy(val2, set, len2);
    sc->arg2 = (uintptr_t)val2;
    sigset_t * val3;
    val3 = arena_alloc(a, len3);
    sc->arg3 = (uintptr_t)val3;
    sc->arg4 = (uintptr_t)nsig;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (val3 != NULL && oldset != NULL) memcpy(oldset, val3, len3);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_rt_sigsuspend(const sigset_t * mask, unsigned long nsig) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len1;
    len1 = sizeof(*mask);
    sc = arena_ensure(a, len1, (syscall_t*) sc);
    sc->syscallno = SYS_rt_sigsuspend;
    sigset_t * val1;
    val1 = arena_alloc(a, len1);
    if (mask != NULL && val1 != NULL) memcpy(val1, mask, len1);
    sc->arg1 = (uintptr_t)val1;
    sc->arg2 = (uintptr_t)nsig;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_rt_sigtimedwait(const sigset_t * set, siginfo_t * info, const struct timespec * timeout, unsigned long nsig) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len1;
    len1 = sizeof(*set);
    size_t len2;
    if (info != NULL ) {
        len2 = sizeof(*info);
    } else {len2 = 0;}
    size_t len3;
    if (timeout != NULL ) {
        len3 = sizeof(*timeout);
    } else {len3 = 0;}
    sc = arena_ensure(a, len1 + len2 + len3, (syscall_t*) sc);
    sc->syscallno = SYS_rt_sigtimedwait;
    sigset_t * val1;
    val1 = arena_alloc(a, len1);
    if (set != NULL && val1 != NULL) memcpy(val1, set, len1);
    sc->arg1 = (uintptr_t)val1;
    siginfo_t * val2;
    if (info != NULL) {
        val2 = arena_alloc(a, len2);
    } else { val2 = NULL; }
    sc->arg2 = (uintptr_t)val2;
    struct timespec * val3;
    if (timeout != NULL) {
        val3 = arena_alloc(a, len3);
        if (timeout != NULL && val3 != NULL) memcpy(val3, timeout, len3);
    } else { val3 = NULL; }
    sc->arg3 = (uintptr_t)val3;
    sc->arg4 = (uintptr_t)nsig;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (info != NULL) {
        if (val2 != NULL && info != NULL) memcpy(info, val2, len2);
    }
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_tkill(int tid, int sig) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    sc->syscallno = SYS_tkill;
    sc->arg1 = (uintptr_t)tid;
    sc->arg2 = (uintptr_t)sig;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_nanosleep(const struct timespec * req, struct timespec * rem) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len1;
    len1 = sizeof(*req);
    size_t len2;
    len2 = sizeof(*rem);
    sc = arena_ensure(a, len1 + len2, (syscall_t*) sc);
    sc->syscallno = SYS_nanosleep;
    struct timespec * val1;
    val1 = arena_alloc(a, len1);
    if (req != NULL && val1 != NULL) memcpy(val1, req, len1);
    sc->arg1 = (uintptr_t)val1;
    struct timespec * val2;
    val2 = arena_alloc(a, len2);
    sc->arg2 = (uintptr_t)val2;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (val2 != NULL && rem != NULL) memcpy(rem, val2, len2);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_clock_getres(clockid_t clk_id, struct timespec * res) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = sizeof(*res);
    sc = arena_ensure(a, len2, (syscall_t*) sc);
    sc->syscallno = SYS_clock_getres;
    sc->arg1 = (uintptr_t)clk_id;
    struct timespec * val2;
    val2 = arena_alloc(a, len2);
    sc->arg2 = (uintptr_t)val2;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (val2 != NULL && res != NULL) memcpy(res, val2, len2);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_clock_gettime(clockid_t clk_id, struct timespec * tp) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len2;
    len2 = sizeof(*tp);
    sc = arena_ensure(a, len2, (syscall_t*) sc);
    sc->syscallno = SYS_clock_gettime;
    sc->arg1 = (uintptr_t)clk_id;
    struct timespec * val2;
    val2 = arena_alloc(a, len2);
    sc->arg2 = (uintptr_t)val2;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = (int)sc->ret_val;
    if (val2 != NULL && tp != NULL) memcpy(tp, val2, len2);
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_gettid() {
    volatile syscall_t *sc;
    volatile uintptr_t __syscall_return_value;
    sc = getsyscallslot(NULL);
    sc->syscallno = SYS_gettid;
    threadswitch((syscall_t*)sc);
    __syscall_return_value = sc->ret_val;
    sc->status = 0;
    return (int)__syscall_return_value;
}

void *host_syscall_SYS_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    volatile syscall_t *sc;
    volatile uintptr_t __syscall_return_value;
    sc = getsyscallslot(NULL);
    sc->syscallno = SYS_mmap;
    sc->arg1 = (uintptr_t)addr;
    sc->arg2 = (uintptr_t)length;
    sc->arg3 = (uintptr_t)prot;
    sc->arg4 = (uintptr_t)flags;
    sc->arg5 = (uintptr_t)fd;
    sc->arg6 = (uintptr_t)offset;
    threadswitch((syscall_t*)sc);
    __syscall_return_value = sc->ret_val;
    sc->status = 0;
    return (void *)__syscall_return_value;
}

void *host_syscall_SYS_mremap(void *old_addr, size_t old_size, size_t new_size, int flags, void *new_addr) {
    volatile syscall_t *sc;
    volatile uintptr_t __syscall_return_value;
    sc = getsyscallslot(NULL);
    sc->syscallno = SYS_mremap;
    sc->arg1 = (uintptr_t)old_addr;
    sc->arg2 = (uintptr_t)old_size;
    sc->arg3 = (uintptr_t)new_size;
    sc->arg4 = (uintptr_t)flags;
    sc->arg5 = (uintptr_t)new_addr;
    threadswitch((syscall_t*)sc);
    __syscall_return_value = sc->ret_val;
    sc->status = 0;
    return (void *)__syscall_return_value;
}

int host_syscall_SYS_munmap(void *addr, size_t length) {
    volatile syscall_t *sc;
    volatile uintptr_t __syscall_return_value;
    sc = getsyscallslot(NULL);
    sc->syscallno = SYS_munmap;
    sc->arg1 = (uintptr_t)addr;
    sc->arg2 = (uintptr_t)length;
    threadswitch((syscall_t*)sc);
    __syscall_return_value = sc->ret_val;
    sc->status = 0;
    return (int)__syscall_return_value;
}

int host_syscall_SYS_msync(void *addr, size_t length, int flags) {
    volatile syscall_t *sc;
    volatile uintptr_t __syscall_return_value;
    sc = getsyscallslot(NULL);
    sc->syscallno = SYS_msync;
    sc->arg1 = (uintptr_t)addr;
    sc->arg2 = (uintptr_t)length;
    sc->arg3 = (uintptr_t)flags;
    threadswitch((syscall_t*)sc);
    __syscall_return_value = sc->ret_val;
    sc->status = 0;
    return (int)__syscall_return_value;
}

/* Some host system calls are only needed for debug purposed. Don't include
 * them in a non-debug build. */
#if DEBUG
int host_syscall_SYS_open(const char *pathname, int flags, mode_t mode) {
    volatile syscall_t *sc;
    volatile intptr_t __syscall_return_value;
    Arena *a = NULL;
    sc = getsyscallslot(&a);
    size_t len1 = 0;
    if (pathname != 0) len1 = strlen(pathname) + 1;
    sc = arena_ensure(a, len1, (syscall_t*) sc);
    sc->syscallno = SYS_open;
    char * val1;
    val1 = arena_alloc(a, len1);
    if (pathname != NULL && val1 != NULL) memcpy(val1, pathname, len1);
    sc->arg1 = (uintptr_t)val1;
    sc->arg2 = (uintptr_t)flags;
    sc->arg3 = (uintptr_t)mode;
    threadswitch((syscall_t*) sc);
    __syscall_return_value = sc->ret_val;
    arena_free(a);
    sc->status = 0;
    return (int)__syscall_return_value;
}
#endif /* DEBUG */
