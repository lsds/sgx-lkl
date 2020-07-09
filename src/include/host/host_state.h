#ifndef SGXLKL_HOST_STATE_H
#define SGXLKL_HOST_STATE_H

#include <host/sgxlkl_host_config.h>
#include <shared/sgxlkl_enclave_config.h>
#include <shared/shared_memory.h>

#define HOST_MAX_DISKS 32

typedef struct sgxlkl_host_disk_state
{
    const sgxlkl_host_mount_config_t*
        mount_config; /* Pointer to disk config (for mounts)*/
    const sgxlkl_host_root_config_t*
        root_config; /* Pointer to root disk config (for root only) */
    int fd;          /* File descriptor */
    char* mmap;      /* Memory map */
    size_t size;     /* Size of disk */
} sgxlkl_host_disk_state_t;

typedef struct sgxlkl_host_state
{
    /* Configuration of the host */
    sgxlkl_host_config_t config;

    /* File descriptor of the network device */
    int net_fd;

    /* Host-side state of disks */
    size_t num_disks;
    sgxlkl_host_disk_state_t disks[HOST_MAX_DISKS];

    /* Shared memory */
    sgxlkl_shared_memory_t shared_memory;

    /* Enclave config */
    sgxlkl_enclave_config_t enclave_config;
} sgxlkl_host_state_t;

extern sgxlkl_host_state_t sgxlkl_host_state;

#endif /* SGXLKL_HOST_STATE_H */