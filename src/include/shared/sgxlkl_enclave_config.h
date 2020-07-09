#ifndef SGXLKL_ENCLAVE_CONFIG_H
#define SGXLKL_ENCLAVE_CONFIG_H

#define MAX_SGXLKL_ETHREADS 1024
#define MAX_SGXLKL_MAX_USER_THREADS 65536

/* Maximum path length of mount points for secondary disks */
#define SGXLKL_DISK_MNT_MAX_PATH_LEN 255

#include <sgxlkl_enclave_config_gen.h>

void sgxlkl_read_enclave_config(
    const char* from,
    sgxlkl_enclave_config_t* to,
    bool enforce_format);

void sgxlkl_free_enclave_config(sgxlkl_enclave_config_t* enclave_config);

/* Check if a disk is configured for encrypted operation */
bool is_encrypted(sgxlkl_enclave_mount_config_t* cfg);

#endif /* SGXLKL_ENCLAVE_CONFIG_H */