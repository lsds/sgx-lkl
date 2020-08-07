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

#define MAX_NET_DEVS 16

static uint8_t registered_dev_idx = 0;

struct virtio_dev* registered_devs[MAX_NET_DEVS];

/*
 * Function to get netdev instance to use its attributes
 */
static inline struct virtio_dev* get_netdev_instance(uint8_t netdev_id)
{
    for (size_t i = 0; i < registered_dev_idx; i++)
        if (registered_devs[i]->vendor_id == netdev_id)
            return registered_devs[i];
    SGXLKL_ASSERT(false);
}

/*
 * Function to register net device & hold the reference
 */
static int dev_register(struct virtio_dev* dev)
{
    int ret = 0;
    if (registered_dev_idx == MAX_NET_DEVS)
    {
        /* This error code is a little bit of a lie */
        sgxlkl_info("Too many virtio_net devices!\n");
        ret = -LKL_ENOMEM;
    }
    else
    {
        /* registered_dev_idx is incremented by the caller */
        registered_devs[registered_dev_idx] = dev;
    }
    return ret;
}

/*
 * Function to generate an interrupt for LKL kernel to reap the virtQ data
 */
static void lkl_deliver_irq(uint64_t dev_id)
{
    struct virtio_dev* dev = get_netdev_instance(dev_id);

    dev->int_status |= VIRTIO_MMIO_INT_VRING;

    lkl_trigger_irq(dev->irq);
}

/*
 * Function to add a new net device to LKL and register the cb to notify
 * frontend driver for the request completion.
 */
int lkl_virtio_netdev_add(struct virtio_dev* netdev)
{
    int ret = -1;

    if (!netdev)
        return -1;

    sgxlkl_ensure_outside(netdev, sizeof(struct virtio_dev));

    int mmio_size = VIRTIO_MMIO_CONFIG + netdev->config_len;

    registered_devs[registered_dev_idx] = netdev;
    if (lkl_virtio_dev_setup(netdev, mmio_size, &lkl_deliver_irq) != 0)
        return -1;

    ret = dev_register(netdev);

    if (ret < 0)
        sgxlkl_info("Failed to register netdev \n");

    return registered_dev_idx++;
}

/*
 * Function to shutdown the network interface and remove it
 */
void lkl_virtio_netdev_remove(void)
{
    uint8_t netdev_id = 0;
    for (netdev_id = 0; netdev_id < registered_dev_idx; netdev_id++)
    {
        sgxlkl_host_netdev_remove(netdev_id);
        int ret = lkl_netdev_get_ifindex(netdev_id);
        if (ret < 0)
            return;
        ret = lkl_if_down(ret);
    }
    return;
}
