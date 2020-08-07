#ifndef SGXLKL_SHARED_MEMORY_H
#define SGXLKL_SHARED_MEMORY_H

#include "shared/oe_compat.h"

#include <shared/vio_event_channel.h>

struct virtio_dev;

typedef struct sgxlkl_shared_memory
{
    /* Shared memory for virtio implementation */
    struct virtio_dev* virtio_net_dev_mem; /* Virtio network device */
    struct virtio_dev* virtio_console_mem; /* Virtio console device */

    size_t evt_channel_num;           /* Number of event channels */
    enc_dev_config_t* enc_dev_config; /* Device configuration */

    void* virtio_swiotlb;       /* Memory for setting up bounce buffer */
    size_t virtio_swiotlb_size; /* Bounce buffer size */

    /* Shared memory for getting time from the host  */
    struct timer_dev* timer_dev_mem;

    /* Shared memory for virtio block devices */
    size_t num_virtio_blk_dev;
    struct virtio_dev** virtio_blk_dev_mem;
    char** virtio_blk_dev_names;

    /* Host environment variables for optional import */
    char* const* env;
    size_t envc;
} sgxlkl_shared_memory_t;

#endif /* SGXLKL_SHARED_MEMORY_H */