#include <errno.h>
#include <linux/virtio_mmio.h>
#include <string.h>
#include "enclave/enclave_oe.h"
#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/ticketlock.h"
#include "enclave/vio_enclave_event_channel.h"
#include "lkl/virtio.h"

/*
 * Function to trigger block dev irq to notify front end driver
 */
static void lkl_deliver_irq(uint8_t dev_id)
{
    struct virtio_dev** mems =
        sgxlkl_enclave_state.shared_memory.virtio_blk_dev_mem;

    sgxlkl_ensure_outside(mems, sizeof(struct virtio_dev*));

    struct virtio_dev* dev = mems[dev_id];

    sgxlkl_ensure_outside(dev, sizeof(struct virtio_dev));

    dev->int_status |= VIRTIO_MMIO_INT_VRING;

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
    struct virtio_dev** mems =
        sgxlkl_enclave_state.shared_memory.virtio_blk_dev_mem;

    sgxlkl_ensure_outside(mems, sizeof(struct virtio_dev*));

    struct virtio_dev* root_dev =
        mems[sgxlkl_enclave_state.disk_state[0].host_disk_index];

    if (!oe_is_outside_enclave(root_dev, sizeof(struct virtio_dev)))
        oe_abort();

    int mmio_size = VIRTIO_MMIO_CONFIG + root_dev->config_len;
    if (lkl_virtio_dev_setup(root_dev, mmio_size, lkl_deliver_irq) != 0)
        return -1;

    for (size_t i = 0; i < num_mounts; ++i)
    {
        struct virtio_dev* dev =
            mems[sgxlkl_enclave_state.disk_state[i + 1].host_disk_index];
        if (!oe_is_outside_enclave(dev, sizeof(struct virtio_dev)))
            oe_abort();
        int mmio_size = VIRTIO_MMIO_CONFIG + dev->config_len;
        if (lkl_virtio_dev_setup(dev, mmio_size, lkl_deliver_irq) != 0)
            return -1;
    }
    return 0;
}
