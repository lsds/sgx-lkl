#ifndef _LKL_SYSCALL_OVERRIDES_FSTAT_H
#define _LKL_SYSCALL_OVERRIDES_FSTAT_H

typedef long (*syscall_handler_t)(long arg1, ...);

syscall_handler_t orig_fstat;

syscall_handler_t orig_newfstatat;

long syscall_fstat_override(int fd, struct stat* stat);

long syscall_newfstatat_override(int dfd, const char *fn,
      struct stat *statbuf, int flag);

#endif