#ifndef SGXLKL_HOST_CONFIG_H
#define SGXLKL_HOST_CONFIG_H

#include <shared/sgxlkl_enclave_config.h>
#include <shared/shared_memory.h>

#define HOST_MAX_DISKS 32

typedef struct sgxlkl_host_disk_state
{
    char* image_path;                           /* Path to image file */
    int fd;                                     /* File descriptor */
    char* mmap;                                 /* Memory map */
    char mnt[SGXLKL_DISK_MNT_MAX_PATH_LEN + 1]; /* Mount point */
    int readonly;                               /* Read-only */
    size_t size;                                /* Size of disk */
} sgxlkl_host_disk_state_t;

typedef struct sgxlkl_host_config
{
    char* thread_affinity;
    char* tap_device;
    bool tap_offload;
} sgxlkl_host_config_t;

typedef struct sgxlkl_host_state
{
    sgxlkl_host_config_t config;

    int net_fd;

    size_t num_disks;
    sgxlkl_host_disk_state_t disks[HOST_MAX_DISKS];

    sgxlkl_shared_memory_t shared_memory;

    sgxlkl_enclave_config_t enclave_config;
} sgxlkl_host_state_t;

#endif /* SGXLKL_HOST_CONFIG_H */