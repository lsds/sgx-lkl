
/* code reused from lkl/tools/lkl/lib/virtio.c and modified
 * to run some part of virtio interface inside enclave */

#include <endian.h>
#include <stdio.h>
#include <string.h>
#include <lkl/iomem.h>
#include <lkl/virtio.h>
#include <enclave/sgxlkl_t.h>
#include <enclave/enclave_util.h>
#include <shared/virtio_ring_buff.h>
#include <stdatomic.h>
#include "enclave/vio_enclave_event_channel.h"
#include <linux/virtio_blk.h>
#include <linux/virtio_mmio.h>

#include "openenclave/corelibc/oestring.h"

// from inttypes.h
#define PRIxPTR "lx"

#define VIRTIO_DEV_MAGIC 0x74726976
#define VIRTIO_DEV_VERSION 2

#undef BIT
#define BIT(x) (1ULL << x)

/* Used for notifying LKL for the list of virtio devices at bootup.
 * Currently block, network and console devices are passed */
char lkl_virtio_devs[4096];

/* pointer to hold the last virtio device entry to lkl_virtio_devs.
 * Each virtio devices entries are separated by a space. */
static char *devs = lkl_virtio_devs;

/* number of virtio device registered before bootup */
static uint32_t lkl_num_virtio_boot_devs;

#define DEVICE_COUNT 32

typedef void (*lkl_virtio_dev_deliver_irq)(uint64_t dev_id);
static lkl_virtio_dev_deliver_irq virtio_deliver_irq[DEVICE_COUNT];

/*
 * virtio_read_device_features: Read Device Features
 * dev : pointer to device structure
 * return the device feature
 */
static inline uint32_t virtio_read_device_features(struct virtio_dev* dev)
{
    if (dev->device_features_sel)
        return (uint32_t)(dev->device_features >> 32);

    return (uint32_t)dev->device_features;
}

/*
 * virtio_read: Process read requests from virtio_mmio
 * data: virtio_dev pointer
 * offset: read request type from virtio_mmio
 * res : pointer to data to be returned
 * size: device options size
 * return: returns 0 on sucess else -LKL_EINVAL on failure.
 */
static int virtio_read(void* data, int offset, void* res, int size)
{
    uint32_t val = 0;
    struct virtio_dev* dev = (struct virtio_dev*)data;

    if (offset >= VIRTIO_MMIO_CONFIG)
    {
        offset -= VIRTIO_MMIO_CONFIG;
        if (offset + size > dev->config_len)
            return -LKL_EINVAL;
        memcpy(res, dev->config_data + offset, size);
        return 0;
    }
    
    if (size != sizeof(uint32_t))
        return -LKL_EINVAL;

    switch (offset)
    {
        case VIRTIO_MMIO_MAGIC_VALUE:
            val = VIRTIO_DEV_MAGIC;
            break;
        case VIRTIO_MMIO_VERSION:
            val = VIRTIO_DEV_VERSION;
            break;
        case VIRTIO_MMIO_DEVICE_ID:
            val = dev->device_id;
            break;
        case VIRTIO_MMIO_VENDOR_ID:
            val = dev->vendor_id;
            break;
        case VIRTIO_MMIO_DEVICE_FEATURES:
            val = virtio_read_device_features(dev);
            break;
        case VIRTIO_MMIO_QUEUE_NUM_MAX:
            val = dev->queue[dev->queue_sel].num_max;
            break;
        case VIRTIO_MMIO_QUEUE_READY:
            val = dev->queue[dev->queue_sel].ready;
            break;
        case VIRTIO_MMIO_INTERRUPT_STATUS:
            val = dev->int_status;
            break;
        case VIRTIO_MMIO_STATUS:
            val = dev->status;
            break;
        case VIRTIO_MMIO_CONFIG_GENERATION:
            val = dev->config_gen;
            break;
        default:
            return -1;
    }

    *(uint32_t*)res = val;

    return 0;
}

/*
 * virtio_write_driver_features: sets driver features.
 * dev: device structure pointer
 * val: feature bits to be configured.
 * return: NONE
 */
static inline void virtio_write_driver_features(
    struct virtio_dev* dev,
    uint32_t val)
{
    uint64_t tmp;

    if (dev->driver_features_sel)
    {
        tmp = dev->driver_features & 0xFFFFFFFF;
        dev->driver_features = tmp | (uint64_t)val << 32;
    }
    else
    {
        tmp = dev->driver_features & 0xFFFFFFFF00000000;
        dev->driver_features = tmp | val;
    }
}

/*
 * blk_check_features: check device and driver features
 * dev: device structure pointer
 * return: if device and driver features are same return 0
 */
static int blk_check_features(struct virtio_dev* dev)
{
    if (dev->driver_features == dev->device_features)
        return 0;

    return -LKL_EINVAL;
}
/* set_status : set the status flag for the device
 * dev : pointer to the device structure.
 * val : Status value to be set for device
 * returns : none
 */
static inline void set_status(struct virtio_dev* dev, uint32_t val)
{
    if ((val & LKL_VIRTIO_CONFIG_S_FEATURES_OK) &&
        (!(dev->driver_features & BIT(LKL_VIRTIO_F_VERSION_1)) ||
         !(dev->driver_features & BIT(LKL_VIRTIO_RING_F_EVENT_IDX)) ||
         blk_check_features(dev)))
        val &= ~LKL_VIRTIO_CONFIG_S_FEATURES_OK;
    dev->status = val;
}

static inline void set_ptr_low(_Atomic(uint64_t) * ptr, uint32_t val)
{
    uint64_t expected = *ptr;
    uint64_t desired;

    do
    {
        desired = (expected & 0xFFFFFFFF00000000) | val;
    } while (!atomic_compare_exchange_weak(ptr, &expected, desired));
}

static inline void set_ptr_high(_Atomic(uint64_t) * ptr, uint32_t val)
{
    uint64_t expected = *ptr;
    uint64_t desired;

    do
    {
        desired = (expected & 0xFFFFFFFF00000000) | val;
        desired = (expected & 0x00000000FFFFFFFF) | ((uint64_t)val << 32);
    } while (!atomic_compare_exchange_weak(ptr, &expected, desired));
}

static void virtio_notify_host_device(struct virtio_dev* dev, uint32_t qidx)
{
    uint8_t dev_id = (uint8_t)dev->vendor_id;
    vio_enclave_notify_enclave_event (dev_id, qidx);
}

/*
 * virtio_write : Handle all write requests to the device from driver
 * data : virtio_dev structure pointer
 * offset : write command
 * res : data to be written
 * size: device options size
 * return 0 if sucess else -LKL_EINVAL
 */
static int virtio_write(void* data, int offset, void* res, int size)
{
    struct virtio_dev* dev = (struct virtio_dev*)data;
    struct virtq* q = &dev->queue[dev->queue_sel];
    uint32_t val;
    int ret = 0;

    if (offset >= VIRTIO_MMIO_CONFIG)
    {
        offset -= VIRTIO_MMIO_CONFIG;

        if (offset + size >= dev->config_len)
            return -LKL_EINVAL;
        memcpy(dev->config_data + offset, res, size);
        atomic_thread_fence(memory_order_seq_cst);
        return 0;
    }

    if (size != sizeof(uint32_t))
        return -LKL_EINVAL;

    val = *(uint32_t*)res;

    switch (offset)
    {
        case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
            if (val > 1)
                return -LKL_EINVAL;
            dev->device_features_sel = val;
            break;
        case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
            if (val > 1)
                return -LKL_EINVAL;
            dev->driver_features_sel = val;
            break;
        case VIRTIO_MMIO_DRIVER_FEATURES:
            virtio_write_driver_features(dev, val);
            break;
        case VIRTIO_MMIO_QUEUE_SEL:
            dev->queue_sel = val;
            break;
        case VIRTIO_MMIO_QUEUE_NUM:
            dev->queue[dev->queue_sel].num = val;
            break;
        case VIRTIO_MMIO_QUEUE_READY:
            dev->queue[dev->queue_sel].ready = val;
            break;
        case VIRTIO_MMIO_QUEUE_NOTIFY:
            virtio_notify_host_device(dev, val);
            break;
        case VIRTIO_MMIO_INTERRUPT_ACK:
            dev->int_status = 0;
            break;
        case VIRTIO_MMIO_STATUS:
            set_status(dev, val);
            break;
        case VIRTIO_MMIO_QUEUE_DESC_LOW:
            set_ptr_low((_Atomic(uint64_t)*)&q->desc, val);
            break;
        case VIRTIO_MMIO_QUEUE_DESC_HIGH:
            set_ptr_high((_Atomic(uint64_t)*)&q->desc, val);
            break;
        case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
            set_ptr_low((_Atomic(uint64_t)*)&q->avail, val);
            break;
        case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
            set_ptr_high((_Atomic(uint64_t)*)&q->avail, val);
            break;
        case VIRTIO_MMIO_QUEUE_USED_LOW:
            set_ptr_low((_Atomic(uint64_t)*)&q->used, val);
            break;
        case VIRTIO_MMIO_QUEUE_USED_HIGH:
            set_ptr_high((_Atomic(uint64_t)*)&q->used, val);
            break;
        default:
            ret = -1;
    }

    return ret;
}

static const struct lkl_iomem_ops virtio_ops = {
    .read = virtio_read,
    .write = virtio_write,
};

/*
 * lkl_virtio_deliver_irq : Deliver the irq request to device task
 * dev_id : Device id for which irq needs to be delivered.
 */
void lkl_virtio_deliver_irq(uint8_t dev_id)
{
    if (virtio_deliver_irq[dev_id])
        virtio_deliver_irq[dev_id](dev_id);
}

/*
 * Function to setup the virtio device setting
 */
int lkl_virtio_dev_setup(
    struct virtio_dev* dev,
    int mmio_size,
    void* deliver_irq_cb)
{
    int avail = 0, num_bytes = 0, ret = 0;
    dev->irq = lkl_get_free_irq("virtio");
    dev->int_status = 0;
    if (dev->irq < 0)
        return 1;

    virtio_deliver_irq[dev->vendor_id] = deliver_irq_cb;
    dev->base = register_iomem(dev, mmio_size, &virtio_ops);

    if (!lkl_is_running())
    {
        avail = sizeof(lkl_virtio_devs) - (devs - lkl_virtio_devs);
        num_bytes = oe_snprintf(
            devs,
            avail,
            " virtio_mmio.device=%d@0x%" PRIxPTR ":%d",
            mmio_size,
            (uintptr_t)dev->base,
            dev->irq);
        if (num_bytes < 0 || num_bytes >= avail)
        {
            lkl_put_irq(dev->irq, "virtio");
            unregister_iomem(dev->base);
            return -LKL_ENOMEM;
        }
        devs += num_bytes;
        dev->virtio_mmio_id = lkl_num_virtio_boot_devs++;
    }
    else
    {
        ret = lkl_sys_virtio_mmio_device_add(
            (long)dev->base, mmio_size, dev->irq);
        if (ret < 0)
        {
            sgxlkl_error("Can't register mmio device\n");
            return -1;
        }
        dev->virtio_mmio_id = lkl_num_virtio_boot_devs + ret;
    }
    return 0;
}
