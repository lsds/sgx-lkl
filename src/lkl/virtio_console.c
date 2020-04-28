#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <linux/virtio_mmio.h>
#include <string.h>
#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/sgxlkl_config.h"
#include "enclave/ticketlock.h"
#include "lkl/virtio.h"

static struct ticketlock __event_notifier_lock;

/*
 * Function to generate an interrupt for LKL kernel to reap the virtQ data
 */
static void lkl_deliver_irq(uint64_t dev_id)
{
    struct virtio_dev* dev = sgxlkl_enclave->shared_memory.virtio_console_mem;

    ticket_lock(&__event_notifier_lock);

    __sync_synchronize();
    dev->int_status |= VIRTIO_MMIO_INT_VRING;

    lkl_trigger_irq(dev->irq);

    ticket_unlock(&__event_notifier_lock);
}

/*
 * Function to add a new net device to LKL
 */
int lkl_virtio_console_add(struct virtio_dev* console)
{
    int ret = -1;

    memset(&__event_notifier_lock, 0, sizeof(struct ticketlock));
    int mmio_size = VIRTIO_MMIO_CONFIG + console->config_len;

    ret = lkl_virtio_dev_setup(console, mmio_size, &lkl_deliver_irq);

    return ret;
}
