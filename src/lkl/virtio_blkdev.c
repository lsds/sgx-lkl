#include <errno.h>
#include <linux/virtio_mmio.h>
#include <string.h>
#include "enclave/enclave_oe.h"
#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/ticketlock.h"
#include "enclave/vio_enclave_event_channel.h"
#include "lkl/virtio.h"

#define MAX_BLOCK_DEVS 32

static uint8_t registered_shadow_dev_idx = 0;

static struct virtio_dev* registered_shadow_devs[MAX_BLOCK_DEVS];

/*
 * Function to get shadow blkdev instance to use its attributes
 */
static inline struct virtio_dev* get_blkdev_instance(uint8_t blkdev_id)
{
    for (size_t i = 0; i < registered_shadow_dev_idx; i++)
        if (registered_shadow_devs[i]->vendor_id == blkdev_id)
            return registered_shadow_devs[i];
    SGXLKL_ASSERT(false);
}

/*
 * Function to trigger block dev irq to notify front end driver
 */
static void lkl_deliver_irq(uint8_t dev_id)
{
    struct virtio_dev* dev = get_blkdev_instance(dev_id);

    dev->int_status |= VIRTIO_MMIO_INT_VRING;
    // TODO might need to update int_status in host as well

    lkl_trigger_irq(dev->irq);
}

/*
 * Function to perform virtio device setup
 */
int lkl_add_disks(
    const sgxlkl_enclave_root_config_t* root,
    const sgxlkl_enclave_mount_config_t* mounts,
    size_t num_mounts)
{
    struct virtio_dev* root_dev = alloc_shadow_virtio_dev();

    if (!root_dev)
        return -1;

    struct virtio_dev* root_dev_host =
        sgxlkl_enclave_state.shared_memory.virtio_blk_dev_mem
        [sgxlkl_enclave_state.disk_state[0].host_disk_index];

    int mmio_size = VIRTIO_MMIO_CONFIG + root_dev_host->config_len;

    registered_shadow_devs[registered_shadow_dev_idx++] = root_dev;

    if (lkl_virtio_dev_setup(root_dev, root_dev_host, mmio_size, lkl_deliver_irq) != 0)
        return -1;

    for (size_t i = 0; i < num_mounts; ++i)
    {
        struct virtio_dev* dev = alloc_shadow_virtio_dev();

        if (!dev)
            return -1;

        struct virtio_dev* dev_host =
            sgxlkl_enclave_state.shared_memory.virtio_blk_dev_mem
                [sgxlkl_enclave_state.disk_state[i + 1].host_disk_index];
        int mmio_size = VIRTIO_MMIO_CONFIG + dev_host->config_len;
        registered_shadow_devs[registered_shadow_dev_idx++] = root_dev;

        if (lkl_virtio_dev_setup(dev, dev_host, mmio_size, lkl_deliver_irq) != 0)
            return -1;
    }
    return 0;
}
