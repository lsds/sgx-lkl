#ifndef SGXLKL_SHARED_MEMORY_H
#define SGXLKL_SHARED_MEMORY_H

#include <stddef.h>

#include <shared/vio_event_channel.h>

typedef struct sgxlkl_enclave_config_shared_memory
{
    void* shm_common;
    void* shm_enc_to_out;
    void* shm_out_to_enc;

    void* vvar;

    /* shared memory for virtio implementation */
    void* virtio_net_dev_mem; /* shared memory for virtio network device */
    void* virtio_console_mem; /* shared memory for virtio console device */
    size_t evt_channel_num;   /* number of event channels */
    enc_dev_config_t* enc_dev_config; /* Device configuration for guest */
    void* virtio_swiotlb;             /* memory for setting up bounce buffer */
    size_t virtio_swiotlb_size;       /* bounce buffer size */

    /* shared memory for getting time from the host  */
    struct timer_dev* timer_dev_mem;

    /* Shared memory between for virtio block device */
    size_t num_virtio_blk_dev;
    void** virtio_blk_dev_mem;
    char** virtio_blk_dev_names;

    /* Host environment variables for optional import */
    char** envp;
} sgxlkl_shared_memory_t;

#endif /* SGXLKL_SHARED_MEMORY_H */