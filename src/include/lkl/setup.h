/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#include "sgx_enclave_config.h"

// 16 MiB is plenty enough of RAM for LKL, except if you want to run tmpfs benchmarks
// (in which case don't edit this, use SGXLKL_LKLRAM environment variable instead)
#define DEFAULT_LKL_RAM (1024*1024*16)
#define DEFAULT_LKL_CMDLINE ""

// Hardcoded encryption key. In an SGX-ready production environment, this would be
// generated on the first run, then sealed and unsealed at each boot.
#define DEFAULT_LKL_DISKENCKEY "01020304050607080910111213141516171819202123242526272829303132"

void __lkl_start_init(enclave_config_t* encl);
void __lkl_exit();

