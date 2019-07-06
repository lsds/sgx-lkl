/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#include "sgx_enclave_config.h"

#define DEFAULT_LKL_CMDLINE ""

void lkl_start_init(enclave_config_t* encl);
void lkl_exit();
void lkl_mount_disks(struct enclave_disk_config* disks, size_t num_disks, const char *cwd);

