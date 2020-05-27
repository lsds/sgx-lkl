#include <errno.h>
#include <linux/virtio_mmio.h>
#include <string.h>
#include "lkl/lkl_util.h"
#include "enclave/sgxlkl_config.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/ticketlock.h"
#include "enclave/vio_enclave_event_channel.h"
#include "lkl/virtio.h"

static struct ticketlock __vio_event_notifier_lock;

/*
 * Function to trigger block dev irq to notify front end driver
 */
static void lkl_deliver_irq(uint8_t dev_id)
{
    ticket_lock(&__vio_event_notifier_lock);

    enclave_disk_config_t* disk = &sgxlkl_enclave->disks[dev_id];
    struct virtio_dev* dev = disk->virtio_blk_dev_mem;

    __sync_synchronize();
    dev->int_status |= VIRTIO_MMIO_INT_VRING;

    lkl_trigger_irq(dev->irq);

    ticket_unlock(&__vio_event_notifier_lock);
}

/*
 * Function to perform virtio device setup
 */
void lkl_add_disks(struct enclave_disk_config* disks, size_t num_disks)
{
    memset(&__vio_event_notifier_lock, 0, sizeof(struct ticketlock));
    for (size_t i = 0; i < num_disks; ++i)
    {
        struct virtio_dev* dev = disks[i].virtio_blk_dev_mem;
        int mmio_size = VIRTIO_MMIO_CONFIG + dev->config_len;
        lkl_virtio_dev_setup(dev, mmio_size, lkl_deliver_irq);
    }
}
