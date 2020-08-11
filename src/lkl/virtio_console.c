#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <linux/virtio_mmio.h>
#include <string.h>
#include "enclave/enclave_oe.h"
#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/ticketlock.h"
#include "lkl/virtio.h"

/*
 * Function to generate an interrupt for LKL kernel to reap the virtQ data
 */
static void lkl_deliver_irq(uint64_t dev_id)
{
    struct virtio_dev* dev =
        sgxlkl_enclave_state.shared_memory.virtio_console_mem;

    dev->int_status |= VIRTIO_MMIO_INT_VRING;

    lkl_trigger_irq(dev->irq);
}

/*
 * Function to add a new net device to LKL
 */
int lkl_virtio_console_add(struct virtio_dev* console)
{
    int ret = -1;

    int mmio_size = VIRTIO_MMIO_CONFIG + console->config_len;

    ret = lkl_virtio_dev_setup(console, mmio_size, &lkl_deliver_irq);

    return ret;
}
