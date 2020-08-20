#ifndef SGXLKL_ENCLAVE_CONFIG_H
#define SGXLKL_ENCLAVE_CONFIG_H

#define MAX_SGXLKL_ETHREADS 1024
#define MAX_SGXLKL_MAX_USER_THREADS 65536

/* Maximum path length of mount points for secondary disks */
#define SGXLKL_DISK_MNT_MAX_PATH_LEN 255

#include <openenclave/bits/defs.h>

#include <sgxlkl_enclave_config_gen.h>

struct config_page
{
    sgxlkl_enclave_config_t config;
} __attribute__((__aligned__(OE_PAGE_SIZE)));

typedef struct config_page sgxlkl_enclave_config_page_t;

const sgxlkl_enclave_config_page_t* sgxlkl_read_enclave_config(
    const char* from,
    bool enforce_format,
    size_t* num_pages);

void sgxlkl_free_enclave_config_page(sgxlkl_enclave_config_page_t* config_page);

/* Check if a disk is configured for encrypted operation */
bool is_encrypted(sgxlkl_enclave_mount_config_t* cfg);

#endif /* SGXLKL_ENCLAVE_CONFIG_H */