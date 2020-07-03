#include <sys/stat.h>
#include <lkl.h>
#include <lkl_host.h>
#include <lkl/asm/stat.h>
#include <string.h>

#include "lkl/syscall-overrides-fstat.h"
#include "enclave/enclave_util.h"

/**
 * The original LKL handler for fstat sycall.
 * The output is a 'lkl_stat' structure, which we will convet to 'stat'
 * structure before returning to user space in the new handler.
 */
static syscall_fstat_handler orig_fstat;

/**
 * The original LKL handler for fstat sycall.
 * The output is a 'lkl_stat' structure, which we will convet to 'stat'
 * structure before returning to user space in the new handler.
 */
static syscall_newfstatat_handler orig_newfstatat;

static void copy_lkl_stat_to_user(struct lkl_stat *lkl_stat, struct stat *stat) {
	stat->st_dev = lkl_stat->st_dev;
	stat->st_ino = lkl_stat->st_ino;
	stat->st_mode = lkl_stat->st_mode;
	stat->st_nlink = lkl_stat->st_nlink;
	stat->st_uid = lkl_stat->st_uid;
	stat->st_gid = lkl_stat->st_gid;
	stat->st_rdev = lkl_stat->st_rdev;
	stat->st_size = lkl_stat->st_size;
	stat->st_blksize = lkl_stat->st_blksize;
	stat->st_blocks = lkl_stat->st_blocks;
	stat->st_atim.tv_sec = lkl_stat->lkl_st_atime;
	stat->st_atim.tv_nsec = lkl_stat->st_atime_nsec;
	stat->st_mtim.tv_sec = lkl_stat->lkl_st_mtime;
	stat->st_mtim.tv_nsec = lkl_stat->st_mtime_nsec;
	stat->st_ctim.tv_sec = lkl_stat->lkl_st_ctime;
	stat->st_ctim.tv_nsec = lkl_stat->st_ctime_nsec;
}

static long syscall_fstat_override(int fd, struct stat* stat) {
    struct lkl_stat lkl_stat = {0};
    long ret;

    if (orig_fstat == NULL)
        sgxlkl_fail("Error: fstat syscall handler not defined");

    ret = orig_fstat(fd, &lkl_stat);
    if (ret == 0)
      copy_lkl_stat_to_user(&lkl_stat, stat);

    return ret;
}

static long syscall_newfstatat_override(
    int dfd, const char *fn, struct stat *stat, int flag) {
    struct lkl_stat lkl_stat = {0};
    long ret;

    if (orig_newfstatat == NULL)
        sgxlkl_fail("Error: newfstatat syscall handler not defined");

    ret = orig_newfstatat(dfd, fn, &lkl_stat, flag);

    if (ret == 0)
        copy_lkl_stat_to_user(&lkl_stat, stat);

    return ret;
}

void syscall_register_fstat_overrides()
{
    orig_fstat = (syscall_fstat_handler)lkl_replace_syscall(
        __lkl__NR_fstat,
        (lkl_syscall_handler_t)syscall_fstat_override);
    orig_newfstatat = (syscall_newfstatat_handler)lkl_replace_syscall(
        __lkl__NR_newfstatat,
        (lkl_syscall_handler_t)syscall_newfstatat_override);
}
