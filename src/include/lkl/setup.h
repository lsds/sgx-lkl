#ifndef SETUP_H
#define SETUP_H

#include "shared/sgxlkl_config.h"

#define DEFAULT_LKL_CMDLINE ""

/* Intialise LKL by booting the kernel */
void lkl_start_init();

/* Mount all LKL disks */
void lkl_mount_disks(
    struct enclave_disk_config* disks,
    size_t num_disks,
    const char* cwd);

/* Shutdown the running LKL kernel */
void lkl_terminate(int exit_status);

#endif /* SETUP_H */