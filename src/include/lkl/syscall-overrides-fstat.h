#ifndef _LKL_SYSCALL_OVERRIDES_FSTAT_H
#define _LKL_SYSCALL_OVERRIDES_FSTAT_H

typedef long (*syscall_fstat_handler)(int, void*);
typedef long (*syscall_newfstatat_handler)(
    int, const char*, void*, int);

// long syscall_fstat_override(int fd, struct stat* stat);

// long syscall_newfstatat_override(int dfd, const char *fn,
      // struct stat *statbuf, int flag);
void syscall_register_fstat_overrides();

#endif