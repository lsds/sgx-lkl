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

static struct virtio_dev* console;

/*
 * Function to generate an interrupt for LKL kernel to reap the virtQ data
 */
static void lkl_deliver_irq(uint64_t dev_id)
{
    struct virtio_dev* dev_host =
        sgxlkl_enclave_state.shared_memory.virtio_console_mem;

    dev_host->int_status |= VIRTIO_MMIO_INT_VRING;
    console->int_status |= VIRTIO_MMIO_INT_VRING;

    lkl_trigger_irq(console->irq);
}

/*
 * Function to add a new net device to LKL
 */
int lkl_virtio_console_add(struct virtio_dev* console_host)
{
    int ret = -1;
    console = alloc_shadow_virtio_dev();

    if (!console)
        return -1;

    int mmio_size = VIRTIO_MMIO_CONFIG + console_host->config_len;
    ret = lkl_virtio_dev_setup(console, console_host, mmio_size, &lkl_deliver_irq);

    return ret;
}
