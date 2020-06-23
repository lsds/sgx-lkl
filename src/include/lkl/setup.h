#ifndef SETUP_H
#define SETUP_H

#include "shared/sgxlkl_enclave_config.h"

#define DEFAULT_LKL_CMDLINE ""

/* Intialise LKL by booting the kernel */
void lkl_start_init();

/* Mount all LKL disks */
void lkl_mount_disks(
    const sgxlkl_enclave_root_config_t* root,
    const sgxlkl_enclave_mount_config_t* mounts,
    size_t num_mounts,
    const char* cwd);

/* Shutdown the running LKL kernel */
void lkl_terminate(int exit_status);

/* Return if LKL is currently terminating */
bool is_lkl_terminating();

#endif /* SETUP_H */