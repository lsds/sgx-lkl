
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

#ifdef PACKED_RING
bool packed_ring = true;
#else
bool packed_ring = false;
#endif

#ifdef DEBUG
#include <openenclave/internal/print.h>
#endif

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
     /* Security Review: use handle instead of virtio_dev pointer. The handle
     * contains two virtio_dev pointers, one for the shadow structure in guest
     * memory, one for the structure in host memory: struct virtio_dev_handle
     * {
     *     struct virtio_dev *dev; //shadow structure in guest memory
     *     struct virtio_dev *dev_host;
     * }
     * dev->queue points to one or more virtq shadow structure. dev_host->queue
     * points to virtq structure(s) in host memory. The desc ring and avail ring
     * of the virtq shadow structure is also shadowed, as they should be
     * host-read-only. The used ring of the virtq shadow structure points to the
     * structure in host side directly, as it should be host-read-write and
     * guest-read-only.
     *
     * For host-read-write members of a shadow structure, perform copy-through
     * read (read from host structure & update the shadow structure). For
     * host-write-once members, read from the shadow structure only, and the
     * shadow structure init routine copy the content from the host structure.
     */
    uint32_t val = 0;
    struct virtio_dev* dev = (struct virtio_dev*)data;

    if (packed_ring)
    {
       oe_host_printf("This is a packed ring\n");
    }

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
        /* Security Review: dev->device_id should be host-write-once */
        case VIRTIO_MMIO_DEVICE_ID:
            val = dev->device_id;
            break;
        /* Security Review: dev->device_id should be host-write-once */
        case VIRTIO_MMIO_VENDOR_ID:
            val = dev->vendor_id;
            break;
        /* Security Review: dev->device_features should be host-write-once */
        case VIRTIO_MMIO_DEVICE_FEATURES:
            val = virtio_read_device_features(dev);
            break;
        /* Security Review: dev->queue[dev->queue_sel].num_max should be
         * host-write-once
         */
        case VIRTIO_MMIO_QUEUE_NUM_MAX:
            val = packed_ring ? dev->packed.queue[dev->queue_sel].num_max :
                                dev->split.queue[dev->queue_sel].num_max;
            break;
        case VIRTIO_MMIO_QUEUE_READY:
            val = packed_ring ? dev->packed.queue[dev->queue_sel].ready :
                                dev->split.queue[dev->queue_sel].ready;
            break;
        /* Security Review: dev->int_status is host-read-write */
        case VIRTIO_MMIO_INTERRUPT_STATUS:
            val = dev->int_status;
            break;
        /* Security Review: dev->status is host-read-write */
        case VIRTIO_MMIO_STATUS:
            val = dev->status;
            break;
        /* Security Review: dev->config_gen should be host-write-once */
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
    /* Security Review: use handle instead of virtio_dev pointer. The handle
     * contains two virtio_dev pointers, one for the shadow structure in guest
     * memory, one for the structure in host memory: struct virtio_dev_handle
     * {
     *     struct virtio_dev *dev; //shadow structure in guest memory
     *     struct virtio_dev *dev_host;
     * }
     * dev->queue points to one or more virtq shadow structure. dev_host->queue
     * points to virtq structure(s) in host memory. The desc ring and avail ring
     * of the virtq shadow structure is also shadowed, as they should be
     * host-read-only. The used ring of the virtq shadow structure points to the
     * structure in host side directly, as it should be host-read-write and
     * guest-read-only.
     *
     * For host-read-only and host-read-write members of a shadow structure,
     * perform copy-through write (write to shadow structure & to host
     * structure). virtq desc and avail ring address handling is a special case.
     */
    struct virtio_dev* dev = (struct virtio_dev*)data;
    struct virtq* split_q = packed_ring ? NULL : &dev->split.queue[dev->queue_sel];
    struct virtq_packed* packed_q = packed_ring ? &dev->packed.queue[dev->queue_sel] : NULL;
    uint32_t val;
    int ret = 0;

    if (offset >= VIRTIO_MMIO_CONFIG)
    {
        offset -= VIRTIO_MMIO_CONFIG;
        /* Security Review: dev->config_data and dev->config_len should be
         * host-write-once
         */
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
        /* Security Review: dev->device_features_sel should be host-read-only */
        case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
            if (val > 1)
                return -LKL_EINVAL;
            dev->device_features_sel = val;
            break;
        /* Security Review: dev->driver_features_sel should be host-read-only */
        case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
            if (val > 1)
                return -LKL_EINVAL;
            dev->driver_features_sel = val;
            break;
        /* Security Review: dev->driver_features should be host-read-only */
        case VIRTIO_MMIO_DRIVER_FEATURES:
            virtio_write_driver_features(dev, val);
            break;
        /* Security Review: dev->queue_sel should be host-read-only */
        case VIRTIO_MMIO_QUEUE_SEL:
            dev->queue_sel = val;
            break;
        /* Security Review: dev->queue[dev->queue_sel].num should be
         * host-read-only
         */
        case VIRTIO_MMIO_QUEUE_NUM:
            if (packed_ring)
                dev->packed.queue[dev->queue_sel].num = val;
            else
                dev->split.queue[dev->queue_sel].num = val;
            break;
        /* Security Review: is dev->queue[dev->queue_sel].ready host-read-only?
         */
        case VIRTIO_MMIO_QUEUE_READY:
            if (packed_ring)
                dev->packed.queue[dev->queue_sel].ready = val;
            else
                dev->split.queue[dev->queue_sel].ready = val;
            break;
        /* Security Review: guest virtio driver(s) writes to virtq desc ring and
         * avail ring in guest memory. In queue notify flow, we need to copy the
         * update to desc ring and avail ring in host memory.
         */
        case VIRTIO_MMIO_QUEUE_NOTIFY:
            virtio_notify_host_device(dev, val);
            break;
        /* Security Review: dev->int_status is host-read-write */
        case VIRTIO_MMIO_INTERRUPT_ACK:
            dev->int_status = 0;
            break;
        /* Security Review: dev->status is host-read-write */
        case VIRTIO_MMIO_STATUS:
            set_status(dev, val);
            break;
        /* Security Review: For Split Queue, q->desc link list
         * content should be host-read-only. The Split Queue implementaiton
         * in guest side virtio code can be affected by host side manipulation
         * of q->desc[].addr and q->desc[].next. Shadowing the desc link list
         * requires extensive changes in the Split Queue code.
         * 
         * For Packed Queue, q->desc link list content is host-read-write, but
         * the Packed Queue implementation in guest side virtio code does not
         * read q->desc[].addr in buffer management flow, instead, maintaining
         * a local copy of the info. So the host side manipulation of
         * q->desc[].addr would not be effective. The Packed Queue
         * implementation still reads q->desc[].length as the size of the data
         * writtern to the "used" buffer, by the host side. Sanity check that
         * q->desc[].length should not exceed buffer size allocated might still
         * be required.
         */
        case VIRTIO_MMIO_QUEUE_DESC_LOW:
            if (packed_ring)
                set_ptr_low((_Atomic(uint64_t)*)&packed_q->desc, val);
            else
                set_ptr_low((_Atomic(uint64_t)*)&split_q->desc, val);
            break;
        case VIRTIO_MMIO_QUEUE_DESC_HIGH:
            if (packed_ring)
                set_ptr_high((_Atomic(uint64_t)*)&packed_q->desc, val);
            else
                set_ptr_high((_Atomic(uint64_t)*)&split_q->desc, val);
            break;
        /* Security Review: For Split Queue, q->avail link list content should be
         * host-read-only. The Split Queue implementaiton
         * in guest side virtio code only write to the avail link list, and does
         * not read from it.As long as the implementaiton does not change, host
         * side manipulation of the avail link list won't be effective. Shadowing
         * the avail linked list has the same challenge as shadowing the desc link
         * list.
         * 
         * For Packed Queue, "avail"/"driver" points to a 32-bit driver-to-device
         * notification. The Packed Queue implementaiton in guest side only writes
         * to it.
         */
        case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
            if (!packed_ring)
                set_ptr_low((_Atomic(uint64_t)*)&split_q->avail, val);
            break;
        case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
            if (!packed_ring)
                set_ptr_high((_Atomic(uint64_t)*)&split_q->avail, val);
            break;
        /* Security Review: For Split Queue, q->used link list content should be
         * guest-read-only. The Split Queue implementaiton in guest side virtio
         * code directly read from the link list and has sanity check for
         * unexpected value of q->used.idx and q->used[].id. It reads
         * q->used[].length as the size of the data writtern to the "used"
         * buffer, by the host side. Sanity check that q->used[].length should
         * not exceed buffer size allocated might still be required.
         * 
         * For Packed Queue, "used"/"device" points to a 32-bit device-to-driver
         * notification. Host side manipulation of "device" flag can only affect
         * functionality.
         */
        case VIRTIO_MMIO_QUEUE_USED_LOW:
            if (!packed_ring)
                set_ptr_low((_Atomic(uint64_t)*)&split_q->used, val);
            break;
        case VIRTIO_MMIO_QUEUE_USED_HIGH:
            if (!packed_ring)
                set_ptr_high((_Atomic(uint64_t)*)&split_q->used, val);
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

    /* Security Review: dev-vendor_id might cause overflow in
     * virtio_deliver_irq[DEVICE_COUNT]
     */
    virtio_deliver_irq[dev->vendor_id] = deliver_irq_cb;
    /* Security Review: pass handle instead of virtio_dev pointer to the rest of
     * the system. 
     */
    /* Security Review: shadow dev->base used in guest side only. No
     * copy-through to the host side structure
     */
    dev->base = register_iomem(dev, mmio_size, &virtio_ops);

    if (!lkl_is_running())
    {
        /* Security Review: multi-thread invocation of this function can cause
         * buffer overflow in lkl_virtio_devs[4096]
         */
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
        /* Security Review: where is dev->virtio_mmio_id used? */
        dev->virtio_mmio_id = lkl_num_virtio_boot_devs++;
    }
    else
    {
        /* Security Review: where is this function defined? */
        ret = lkl_sys_virtio_mmio_device_add(
            (long)dev->base, mmio_size, dev->irq);
        if (ret < 0)
        {
            sgxlkl_error("Can't register mmio device\n");
            return -1;
        }
        /* Security Review: where is dev->virtio_mmio_id used? */
        dev->virtio_mmio_id = lkl_num_virtio_boot_devs + ret;
    }
    return 0;
}
