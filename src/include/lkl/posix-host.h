#ifndef _POSIX_HOST_H
#define _POSIX_HOST_H

#include <lkl_host.h>

struct lkl_mutex;

struct lkl_sem;

extern struct lkl_host_operations sgxlkl_host_ops;
extern struct lkl_dev_blk_ops sgxlkl_dev_blk_ops;
extern struct lkl_dev_blk_ops sgxlkl_dev_blk_mem_ops;
#endif
