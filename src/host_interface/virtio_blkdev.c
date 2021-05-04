#include <assert.h>
#include <errno.h>
#include <host/host_state.h>
#include <host/sgxlkl_u.h>
#include <host/sgxlkl_util.h>
#include <host/vio_host_event_channel.h>
#include <host/virtio_blkdev.h>
#include <host/virtio_debug.h>
#include <shared/env.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define min_len(a, b) (a < b ? a : b)

#define HOST_BLK_DEV_NUM_QUEUES 1
#define HOST_BLK_DEV_QUEUE_DEPTH 32

extern sgxlkl_host_state_t sgxlkl_host_state;

#if DEBUG && VIRTIO_TEST_HOOK
#include <stdio.h>
static uint64_t virtio_blk_req_cnt;
#endif // DEBUG && VIRTIO_TEST_HOOK

/*
 * Function to return the disk configuration associated to dev_id. Disk
 * configuration is used to perform the disk read and write.
 */
static inline sgxlkl_host_disk_state_t* get_disk_config(uint8_t blkdev_id)
{
    sgxlkl_host_disk_state_t* disk = &sgxlkl_host_state.disks[blkdev_id];
    assert(disk != NULL);
    return disk;
}

/*
 * Virtio callback functions for processing virtio requests
 */
static int blk_enqueue(struct virtio_dev* dev, int q, struct virtio_req* req)
{
    struct virtio_blk_outhdr* h;
    struct virtio_blk_req_trailer* t;
    size_t offset;
    int ret;

    sgxlkl_host_disk_state_t* disk = get_disk_config(dev->vendor_id);
    int fd = disk->fd;

    if (req->buf_count < 3)
        goto out;


    h = req->buf[0].iov_base;
    t = req->buf[req->buf_count - 1].iov_base;

    t->status = LKL_DEV_BLK_STATUS_IOERR;

    if (req->buf[0].iov_len != sizeof(*h))
        goto out;

    if (req->buf[req->buf_count - 1].iov_len != sizeof(*t))
        goto out;

    offset = h->sector * 512;

    switch (h->type)
    {
        case LKL_DEV_BLK_TYPE_READ:
            ret = pread(fd, req->buf[1].iov_base, req->buf[1].iov_len, offset);
            break;
        case LKL_DEV_BLK_TYPE_WRITE:
            ret = pwrite(fd, req->buf[1].iov_base, req->buf[1].iov_len, offset);
            break;
        case LKL_DEV_BLK_TYPE_FLUSH:
        case LKL_DEV_BLK_TYPE_FLUSH_OUT:
            ret = fsync(fd);
            break;
        default:
            ret = LKL_DEV_BLK_STATUS_UNSUP;
    }
    t->status = ret;

out:
    virtio_req_complete(req, 0);
    return 0;
}

/*
 * Virtio callback function to check the features supported
 */
static int blk_check_features(struct virtio_dev* dev)
{
    if (dev->driver_features == dev->device_features)
        return 0;

    return -EINVAL;
}

static struct virtio_dev_ops _host_blk_ops = {
    .check_features = blk_check_features,
    .enqueue = blk_enqueue,
};

/*
 * blk_device_init: initialize block device
 * disk-- input disk structure to initialize block device
 */
int blk_device_init(
    sgxlkl_host_disk_state_t* disk,
    size_t disk_index,
    int enable_swiotlb)
{

    void* vq_mem = NULL;
    struct virtio_blk_dev* host_blk_device = NULL;
    size_t bdev_size = sizeof(struct virtio_blk_dev);
    size_t vq_size;

    if (!packed_ring)
        vq_size = HOST_BLK_DEV_NUM_QUEUES * sizeof(struct virtq);
    else
        vq_size = HOST_BLK_DEV_NUM_QUEUES * sizeof(struct virtq_packed);

    /*Allocate memory for block device*/
    bdev_size = next_pow2(bdev_size);
    host_blk_device = mmap(
        0,
        bdev_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0);
    if (!host_blk_device)
    {
        sgxlkl_host_fail("%s: block device mem allocation failed\n", __func__);
        return -1;
    }

    /*Allocate memory for virtio queue*/
    vq_size = next_pow2(vq_size);
    vq_mem = mmap(
        0, vq_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!vq_mem)
    {
        sgxlkl_host_fail("%s: block device queue mem alloc failed\n", __func__);
        return -1;
    }

    /* Initialize block device */
    if (!packed_ring)
    {
        host_blk_device->dev.split.queue = vq_mem;
        memset(host_blk_device->dev.split.queue, 0, vq_size);
    }
    else
    {
        host_blk_device->dev.packed.queue = vq_mem;
        memset(host_blk_device->dev.packed.queue, 0, vq_size);
    }
    for (int i = 0; i < HOST_BLK_DEV_NUM_QUEUES; i++)
    {
        if (!packed_ring)
        {
            host_blk_device->dev.split.queue[i].num_max = HOST_BLK_DEV_QUEUE_DEPTH;
        }
        else
        {
            host_blk_device->dev.packed.queue[i].num_max = HOST_BLK_DEV_QUEUE_DEPTH;
            host_blk_device->dev.packed.queue[i].device_wrap_counter = 1;
            host_blk_device->dev.packed.queue[i].driver_wrap_counter = 1;
        }
    }

    host_blk_device->config.capacity = disk->size / 512;

    /* Initialize virtio dev */
    host_blk_device->dev.device_id = VIRTIO_ID_BLOCK;
    host_blk_device->dev.vendor_id = disk_index;
    host_blk_device->dev.config_gen = 0;
    host_blk_device->dev.config_data = &host_blk_device->config;
    host_blk_device->dev.config_len = sizeof(host_blk_device->config);
    host_blk_device->dev.ops = &_host_blk_ops;
    host_blk_device->dev.int_status = 0;
    host_blk_device->dev.device_features |=
        BIT(VIRTIO_F_VERSION_1) | BIT(VIRTIO_RING_F_EVENT_IDX);

    if (packed_ring)
        host_blk_device->dev.device_features |= BIT(VIRTIO_F_RING_PACKED);

    if (enable_swiotlb)
        host_blk_device->dev.device_features |= BIT(VIRTIO_F_IOMMU_PLATFORM);

    sgxlkl_host_state.shared_memory.virtio_blk_dev_mem[disk_index] =
        &host_blk_device->dev;
    sgxlkl_host_state.shared_memory.virtio_blk_dev_names[disk_index] =
        strdup(disk->root_config ? "/" : disk->mount_config->destination);

    return 0;
}

/*
 * blkdevice_thread :
 * Block device thread handles all the virtio queue requests.
 * Block device configuration is used for monitoring eventQ
 */
void* blkdevice_thread(void* arg)
{
    host_dev_config_t* cfg = arg;

    /* time (in ms) for waiting for an event from enclave */
    int timeout_ms = 10;

    for (;;)
    {
        vio_host_process_enclave_event(cfg->dev_id, timeout_ms);

        if (vio_host_check_guest_shutdown_evt())
            continue;

        struct virtio_dev* dev =
            sgxlkl_host_state.shared_memory.virtio_blk_dev_mem[cfg->dev_id];
        virtio_process_queue(dev, 0);
#if DEBUG && VIRTIO_TEST_HOOK
        uint64_t vio_req_cnt = virtio_debug_blk_get_ring_count();
        if ((vio_req_cnt) && !(virtio_blk_req_cnt++ % vio_req_cnt))
            virtio_debug_set_evt_chn_state(true);
#endif
    }
    return NULL;
}
