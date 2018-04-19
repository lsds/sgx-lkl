/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * 
 * This file is part of SGX-LKL.
 * 
 * SGX-LKL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SGX-LKL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SGX-LKL.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HOSTSYSCALLS_H
#define HOSTSYSCALLS_H
#define _GNU_SOURCE
#define _BSD_SOURCE

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <poll.h>
#include "hostmem.h"

/* 
 * hostsyscalls.c must include ksigaction.h before including this header.
 */
typedef struct k_sigaction k_sigaction_t;

int host_syscall_SYS_clock_getres(clockid_t clk_id, struct timespec *res);
int host_syscall_SYS_clock_gettime(clockid_t clk_id, struct timespec *tp);
int host_syscall_SYS_close(int fd);
void host_syscall_SYS_exit(int status);
void host_syscall_SYS_exit_group(int status);
int host_syscall_SYS_fcntl(int fd, intptr_t cmd, intptr_t arg);
int host_syscall_SYS_fdatasync(int fd);
int host_syscall_SYS_fstat(int fd, struct stat *buf);
pid_t host_syscall_SYS_gettid(void);
int host_syscall_SYS_ioctl(int fd, unsigned long request, void *arg);
off_t host_syscall_SYS_lseek(int fd, off_t offset, int whence);
void *host_syscall_SYS_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int host_syscall_SYS_mprotect(void *addr, size_t len, int prot);
void *host_syscall_SYS_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);
int host_syscall_SYS_munmap(void *addr, size_t length);
int host_syscall_SYS_msync(void *addr, size_t length, int flags);
int host_syscall_SYS_nanosleep(const struct timespec *req, struct timespec *rem);
ssize_t host_syscall_SYS_read(int fd, void *buf, size_t count);
ssize_t host_syscall_SYS_readv(int fd, struct iovec *iov, int iovcnt);
int host_syscall_SYS_pipe(int pipefd[2]);
int host_syscall_SYS_pipe2(int pipefd[2], int flags);
int host_syscall_SYS_poll(struct pollfd *fds, nfds_t nfds, int timeout);
ssize_t host_syscall_SYS_preadv(int fd, struct iovec *iov, int iovcnt, off_t offset, long ofs32);
ssize_t host_syscall_SYS_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset, long ofs32);
ssize_t host_syscall_SYS_pread64(int fd, void *buf, size_t count, off_t offset);
ssize_t host_syscall_SYS_pwrite64(int fd, const void *buf, size_t count, off_t offset);
int host_syscall_SYS_rt_sigaction(int signum, struct sigaction *act, struct sigaction *oldact, unsigned long nsig);
int host_syscall_SYS_rt_sigpending(sigset_t *set, unsigned long nsig);
int host_syscall_SYS_rt_sigprocmask(int how, void *set, sigset_t *oldset, unsigned long nsig);
int host_syscall_SYS_rt_sigsuspend(const sigset_t *mask, unsigned long nsig);
int host_syscall_SYS_rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout, unsigned long nsig);
int host_syscall_SYS_tkill(int tid, int sig);
ssize_t host_syscall_SYS_write(int fd, const void *buf, size_t count);
ssize_t host_syscall_SYS_writev(int fd, const struct iovec *iov, int iovcnt);

/* Currently unsupported */
uintptr_t host_syscall_SYS_brk(int inc);
int host_syscall_SYS_kill(pid_t pid, int sig);
int host_syscall_SYS_sigaltstack(const stack_t *ss, stack_t *oss);

/* No-ops */
int host_syscall_SYS_munlockall(void);
long host_syscall_SYS_set_tid_address(int *tidptr);

/* Handled within enclave */
/* TODO: Move declarations to separate headers */
int syscall_SYS_futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3);
void *syscall_SYS_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void *syscall_SYS_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);
int syscall_SYS_msync(void *addr, size_t length, int flags);
int syscall_SYS_munmap(void *addr, size_t length);

#endif /* HOSTSYSCALLS_H */
