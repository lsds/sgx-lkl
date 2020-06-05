#ifndef SGXLKL_HOST_CONFIG_H
#define SGXLKL_HOST_CONFIG_H

#include <shared/enclave_config.h>
#include <shared/shared_memory.h>

#define HOST_MAX_DISKS 32

typedef struct sgxlkl_host_disk_state
{
    /* Provided by sgx-lkl-run at runtime. */
    int fd;
    size_t size;
    char* mmap;
    bool is_encrypted;
    char mnt[SGXLKL_DISK_MNT_MAX_PATH_LEN + 1]; // mount point ("/" for root
                                                // disk)
    int ro;                                     // Read-only?
    char* key;                                  // Encryption key
    size_t key_len;                             // Key length
    char* roothash;                             // Root hash (for dm-verity)
    size_t roothash_offset; // Merkle tree offset (for dm-verity)

    int is_mounted; // Has been mounted
} sgxlkl_host_disk_state_t;

typedef struct sgxlkl_host_state
{
    size_t num_disks;
    sgxlkl_host_disk_state_t disks[HOST_MAX_DISKS];

    sgxlkl_shared_memory_t shared_memory;

    sgxlkl_enclave_config_t enclave_config;
} sgxlkl_host_state_t;

#endif /* SGXLKL_HOST_CONFIG_H */