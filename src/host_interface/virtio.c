
/* code reused from lkl/tools/lkl/lib/virtio.c */

#include <host/sgxlkl_u.h>
#include <host/sgxlkl_util.h>
#include <host/vio_host_event_channel.h>
#include <host/virtio_blkdev.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define min_len(a, b) (a < b ? a : b)

struct _virtio_req
{
    struct virtio_req req;
    struct virtio_dev* dev;
    struct virtq* q;
    uint16_t idx;
};

/*
 * vring_desc_at_avail_idx : get the pointer to vring descriptor
 *                           at given available index from virtio_queue
 * virtio_queue : pointer to virtio queue
 * idx : available ring index
 */
static inline struct virtq_desc* vring_desc_at_avail_idx(
    struct virtq* q,
    uint16_t idx)
{
    uint16_t desc_idx = q->avail->ring[idx & (q->num - 1)];
    return &q->desc[desc_idx & (q->num - 1)];
}

/*
 * add_dev_buf_from_vring_desc:
 * read data buffer address from vring descriptors into local buffers
 * req : local buffer
 * vring_desc : virtio ring descriptor
 */
static void add_dev_buf_from_vring_desc(
    struct virtio_req* req,
    struct virtq_desc* vring_desc)
{
    struct iovec* buf = &req->buf[req->buf_count++];

    buf->iov_base = (void*)(uintptr_t)(vring_desc->addr);
    buf->iov_len = vring_desc->len;

    req->total_len += buf->iov_len;
}

/*
 * get_next_desc : get next vring rescriptor pointer
 * q: Virtio queue
 * desc: current descriptor
 * idx : available ring index
 */
static struct virtq_desc* get_next_desc(
    struct virtq* q,
    struct virtq_desc* desc,
    uint16_t* idx)
{
    uint16_t desc_idx;

    if (q->max_merge_len)
    {
        if (++(*idx) == q->avail->idx)
            return NULL;
        desc_idx = q->avail->ring[*idx & (q->num - 1)];
        return &q->desc[desc_idx & (q->num - 1)];
    }

    if (!(desc->flags & LKL_VRING_DESC_F_NEXT))
        return NULL;
    return &q->desc[desc->next & (q->num - 1)];
}

/*
 * virtio_add_used: update used ring at used index with used discriptor index
 * q : input parameter
 * used_idx : input parameter
 * avail_idx: input parameter
 * len : input parameter
 */
static inline void virtio_add_used(
    struct virtq* q,
    uint16_t used_idx,
    uint16_t avail_idx,
    uint16_t len)
{
    uint16_t desc_idx = q->avail->ring[avail_idx & (q->num - 1)];

    used_idx = used_idx & (q->num - 1);
    q->used->ring[used_idx].id = desc_idx;
    q->used->ring[used_idx].len = htole16(len);
}

/*
 * virtio_sync_used_idx: update used index
 * q: virtio queue
 * idx: index value to be updated in used index
 */
static inline void virtio_sync_used_idx(struct virtq* q, uint16_t idx)
{
    /* Make sure all memory writes before are visible to driver before updating
     * the idx. */
    __sync_synchronize();
    q->used->idx = htole16(idx);
}

/*
 * virtio_get_used_idx : get used index from virtio queue
 * q: virtio queue pointer
 */
static inline uint16_t virtio_get_used_idx(struct virtq* q)
{
    return le16toh(q->used->idx);
}

/*
 * virtio_get_used_event : get current descriptor index from avail ring.
 * q: virtio queue
 */
static inline uint16_t virtio_get_used_event(struct virtq* q)
{
    return q->avail->ring[q->num];
}

static inline int lkl_vring_need_event(
    uint16_t event_idx,
    uint16_t new_idx,
    uint16_t old)
{
    return (uint16_t)(new_idx - event_idx - 1) < (uint16_t)(new_idx - old);
}

/*
 * notify the device task in enclave for the host event
 */
static inline void virtio_deliver_irq(struct virtio_dev* dev)
{
    vio_host_notify_host_event(dev->vendor_id);
}

/*
 * virtio_req_complete: handle finishing activities after processing request
 * req: local virtio request buffer
 * len: length of the data processed
 */
void virtio_req_complete(struct virtio_req* req, uint32_t len)
{
    int send_irq = 0;
    struct _virtio_req* _req = container_of(req, struct _virtio_req, req);
    struct virtq* q = _req->q;
    uint16_t avail_idx = _req->idx;
    uint16_t used_idx = virtio_get_used_idx(_req->q);

    /*
     * We've potentially used up multiple (non-chained) descriptors and have
     * to create one "used" entry for each descriptor we've consumed.
     */
    for (int i = 0; i < req->buf_count; i++)
    {
        uint16_t used_len;

        if (!q->max_merge_len)
            used_len = len;
        else
            used_len = min_len(len, req->buf[i].iov_len);

        virtio_add_used(q, used_idx++, avail_idx++, used_len);

        len -= used_len;
        if (!len)
            break;
    }
    virtio_sync_used_idx(q, used_idx);
    q->last_avail_idx = avail_idx;

    /*
     * Triggers the irq whenever there is no available buffer.
     */
    if (q->last_avail_idx == le16toh(q->avail->idx))
        send_irq = 1;

    /*
     * There are two rings: q->avail and q->used for each of the rx and tx
     * queues that are used to pass buffers between kernel driver and the
     * virtio device implementation.
     *
     * Kernel maitains the first one and appends buffers to it. In rx queue,
     * it's empty buffers kernel offers to store received packets. In tx
     * queue, it's buffers containing packets to transmit. Kernel notifies
     * the device by mmio write (see VIRTIO_MMIO_QUEUE_NOTIFY below).
     *
     * The virtio device (here in this file) maintains the
     * q->used and appends buffer to it after consuming it from q->avail.
     *
     * The device needs to notify the driver by triggering irq here. The
     * LKL_VIRTIO_RING_F_EVENT_IDX is enabled in this implementation so
     * kernel can set virtio_get_used_event(q) to tell the device to "only
     * trigger the irq when this item in q->used ring is populated."
     *
     * Because driver and device are run in two different threads. When
     * driver sets virtio_get_used_event(q), q->used->idx may already be
     * increased to a larger one. So we need to trigger the irq when
     * virtio_get_used_event(q) < q->used->idx.
     *
     * To avoid unnessary irqs for each packet after
     * virtio_get_used_event(q) < q->used->idx, last_used_idx_signaled is
     * stored and irq is only triggered if
     * last_used_idx_signaled <= virtio_get_used_event(q) < q->used->idx
     *
     * This is what lkl_vring_need_event() checks and it evens covers the
     * case when those numbers wrap up.
     */
    if (send_irq || lkl_vring_need_event(
                        le16toh(virtio_get_used_event(q)),
                        virtio_get_used_idx(q),
                        q->last_used_idx_signaled))
    {
        q->last_used_idx_signaled = virtio_get_used_idx(q);
        virtio_deliver_irq(_req->dev);
    }
}

/*
 * virtio_process_one: Process one queue at a time
 * dev: device structure pointer
 * qidx: queue index to be processed
 */
static int virtio_process_one(struct virtio_dev* dev, int qidx)
{
    struct virtq* q = &dev->queue[qidx];
    uint16_t idx = q->last_avail_idx;

    struct _virtio_req _req = {
        .dev = dev,
        .q = q,
        .idx = idx,
    };

    struct virtio_req* req = &_req.req;
    memset(req, 0, sizeof(struct virtio_req));
    struct virtq_desc* desc = vring_desc_at_avail_idx(q, idx);
    do
    {
        add_dev_buf_from_vring_desc(req, desc);
        if (q->max_merge_len && req->total_len > q->max_merge_len)
            break;
        desc = get_next_desc(q, desc, &idx);
    } while (desc && req->buf_count < VIRTIO_REQ_MAX_BUFS);

    // Return result of enqueue operation
    return dev->ops->enqueue(dev, qidx, req);
}

static inline void virtio_set_avail_event(struct virtq* q, uint16_t val)
{
    *((uint16_t*)&q->used->ring[q->num]) = val;
}

void virtio_set_queue_max_merge_len(struct virtio_dev* dev, int q, int len)
{
    dev->queue[q].max_merge_len = len;
}

/*
 * virtio_process_queue : process all the requests in the specific queue
 * dev: virtio device structure pointer
 * qidx: queue index to be processed
 * fd: disk file descriptor
 */
void virtio_process_queue(struct virtio_dev* dev, uint32_t qidx)
{
    struct virtq* q = &dev->queue[qidx];

    if (!q->ready)
        return;

    if (dev->ops->acquire_queue)
        dev->ops->acquire_queue(dev, qidx);

    while (q->last_avail_idx != q->avail->idx)
    {
        /* Make sure following loads happens after loading q->avail->idx */
        if (virtio_process_one(dev, qidx) < 0)
            break;
        if (q->last_avail_idx == le16toh(q->avail->idx))
            virtio_set_avail_event(q, q->avail->idx);
    }

    if (dev->ops->release_queue)
        dev->ops->release_queue(dev, qidx);
}
