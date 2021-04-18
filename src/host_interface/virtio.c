
/* code reused from lkl/tools/lkl/lib/virtio.c */

#include <host/sgxlkl_u.h>
#include <host/sgxlkl_util.h>
#include <host/vio_host_event_channel.h>
#include <host/virtio_blkdev.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define min_len(a, b) (a < b ? a : b)

#ifdef PACKED_RING
bool packed_ring = true;
#else
bool packed_ring = false;
#endif

struct _virtio_req
{
    union {
        struct {
            virtq* q;
        }split;
        struct {
            virtq* q;
        }packed;
    };
    struct virtio_req req;
    struct virtio_dev* dev;

    uint16_t idx;
};

/*
 * packed_desc_is_avail: Check if the current descriptor
 *                       the driver is expected to fill in is available
 * q: pointer to a packed virtio queue
 */
static int packed_desc_is_avail(struct virtq_packed* q)
{
    struct virtq_packed_desc* desc = q->desc[q->avail_desc_idx & (q->num -1)];
    uint16_t avail = desc->flags & KL_VRING_PACKED_DESC_F_AVAIL;
    uint16_t used = desc->flags & KL_VRING_PACKED_DESC_F_USED;
    return avail != used && avail == q->driver_wrap_counter;
}

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
 * add_dev_buf_from_vring_desc_split:
 * read data buffer address from split vring descriptors into local buffers
 * req : local buffer
 * vring_desc_split : virtio ring descriptor
 */
static void add_dev_buf_from_vring_desc_split(
    struct virtio_req* req,
    struct virtq_desc* vring_desc_split)
{
    struct iovec* buf = &req->buf[req->buf_count++];

    buf->iov_base = (void*)(uintptr_t)(vring_desc_split->addr);
    buf->iov_len = vring_desc_split->len;

    req->total_len += buf->iov_len;
}

/*
 * add_dev_buf_from_vring_desc_packed:
 * read data buffer address from packed vring descriptors into local buffers
 * req : local buffer
 * vring_desc_packed : virtio ring descriptor
 */
static void add_dev_buf_from_vring_desc_packed(
    struct virtio_req* req,
    struct virtq_packed_desc* vring_desc_packed)
{
    struct iovec* buf = &req->buf[req->buf_count++];

    buf->iov_base = (void*)(uintptr_t)(vring_desc_packed->addr);
    buf->iov_len = vring_desc_packed->len;

    req->total_len += buf->iov_len;
}

/*
 * get_next_desc : get next split vring descriptor pointer
 * q: Virtio queue
 * desc: current descriptor
 * idx : available ring index
 */
static struct virtq_desc* get_next_desc_split(
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
 * get_next_desc : get next packed vring descriptor pointer
 * q: Virtio queue
 * desc: current descriptor
 * idx : available ring index
 */
static struct virtq_packed_desc* get_next_desc_packed(
    struct virtq_packed* q,
    struct virtq_packed_desc* desc,
    uint16_t* idx)
{
    if (q->max_merge_len)
    {
        if (++(*idx) == q->num_max)
            return NULL;
        struct virtq_packed_desc* next_desc = q->desc[*idx & (q->num-1)];
        packed_desc_is_avail(next_desc) ? next_desc : NULL;
    }

    if (!(desc->flags & LKL_VRING_DESC_F_NEXT))
        return NULL;
    return &q->desc[++(*idx) & (q->num - 1)];
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

static inline void virtio_add_used_packed(
    struct virtq_packed* q,
    uint16_t used_idx,
    uint32_t len,
    uint16_t id)
{
    struct virtq_packed_desc* desc = q->desc[used_idx & (q->num -1)];
    desc->id = id;
    desc->len = htole32(len);
    desc->flags |=
        q->device_wrap_counter << LKL_VRING_PACKED_DESC_F_AVAIL |
        q->device_wrap_counter << LKL_VRING_PACKED_DESC_F_USED;
    desc->flags = htole16(desc->flags);
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
void virtio_req_complete_split(struct virtio_req* req, uint32_t len)
{
    int send_irq = 0;
    struct _virtio_req* _req = container_of(req, struct _virtio_req, req);
    struct virtq* q = _req->split.q;
    uint16_t avail_idx = _req->idx;
    uint16_t used_idx = virtio_get_used_idx(_req->split.q);

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
 * virtio_req_complete: handle finishing activities after processing request
 * req: local virtio request buffer
 * len: length of the data processed
 */
void virtio_req_complete_packed(struct virtio_req* req, uint32_t len)
{
    /**
     * Requirements for this:
     *  Setting a single used desc for a descriptor chain
     *  Ensuring the id of a used desc for a desc chain is the id of the last buffer in the chain
     *  avail_desc_idx and used_desc_idx to be incremented and wrapped around as appropriate
     *  changing the wrap counters when the above are wrapped around
     *

        This function only gets called either with chained descriptors,
        or max_merge_len (which I assume would also be chained descriptors).

        I know this as for example it gets called from blk_enqueue,
        whose request is chained, and the same with network device
        (and I assume the same for console)
     */
    int send_irq = 0;
    struct _virtio_req* _req = container_of(req, struct _virtio_req, req);
    struct virtq_packed* q = _req->packed.q;
    uint16_t avail_desc_idx = _req->idx;
    uint16_t used_desc_idx = q->used_desc_idx;
    uint16_t last_buffer_idx = avail_desc_idx+(req->buff_count-1);
    uint16_t used_len;
    if (!q->max_merge_len)
        used_len = len;
    else
        used_len = min_len(len, req->buf[req->buff_count-1].iov_len);

    struct virtq_packed_desc* desc = q->desc[last_buffer_idx & (q->num -1)];
    virtio_add_used_packed(q, used_desc_idx, used_len, desc->id);

    used_desc_idx += req->buff_count;
    avail_desc_idx += req->buff_count;

    if (used_desc_idx >= q->num)
    {
        used_desc_idx -= q->num;
        q->device_wrap_counter = !q->device_wrap_counter;
    }

    if (avail_desc_idx >= q->num)
    {
        avail_desc_idx -= q->num;
        q->driver_wrap_counter = !q->driver_wrap_counter;
        send_irq = 1;
    }

    // Don't think we need to synchronise used
    q->used_desc_idx = used_desc_idx;
    q->avail_desc_idx = avail_desc_idx;


    /**TODO*/
    // Need to use event supression here - but in theory this should work
    if (send_irq)
    {
        virtio_deliver_irq(_req->dev);
    }
}

/*
 * virtio_req_complete: handle finishing activities after processing request
 * req: local virtio request buffer
 * len: length of the data processed
 */
void virtio_req_complete(struct virtio_req* req, uint32_t len)
{
    packed_ring ? virtio_req_complete_packed(req, len) :
                  virtio_req_complete_split(req, len);
}

/*
 * virtio_process_one: Process one split queue at a time
 * dev: device structure pointer
 * qidx: queue index to be processed
 */
static int virtio_process_one_split(struct virtio_dev* dev, int qidx)
{
    struct virtq* q = &dev->queue[qidx];
    uint16_t idx = q->last_avail_idx;

    struct _virtio_req _req = {
        .dev = dev,
        .split.q = q,
        .idx = idx,
    };

    struct virtio_req* req = &_req.req;
    memset(req, 0, sizeof(struct virtio_req));
    struct virtq_desc* desc = vring_desc_at_avail_idx(q, idx);
    do
    {
        add_dev_buf_from_vring_desc_split(req, desc);
        if (q->max_merge_len && req->total_len > q->max_merge_len)
            break;
        desc = get_next_desc_split(q, desc, &idx);
    } while (desc && req->buf_count < VIRTIO_REQ_MAX_BUFS);

    // Return result of enqueue operation
    return dev->ops->enqueue(dev, qidx, req);
}

/*
 * virtio_process_one: Process one packed queue at a time
 * dev: device structure pointer
 * qidx: queue index to be processed
 */
static int virtio_process_one_packed(struct virtio_dev* dev, int qidx)
{
    struct virtq_packed* q = &dev->queue[qidx];
    uint16_t idx = q->avail_desc_idx;

    struct _virtio_req _req = {
        .dev = dev,
        .packed.q = q,
        .idx = idx,
    };

    struct virtio_req* req = &_req.req;
    struct virtq_packed_desc* desc = q->desc[idx & (q->num - 1)];
    do
    {
        add_dev_buf_from_vring_desc_packed(req, desc);
        // Do we need this
        if (q->max_merge_len && req->total_len > q->max_merge_len)
            break;
        desc = get_next_desc_packed(q, desc, &idx);
    } while (desc && req->buf_count < VIRTIO_REQ_MAX_BUFS);

    // Return result of enqueue operation
    return dev->ops->enqueue(dev, qidx, req);
}

static inline void virtio_set_avail_event(struct virtq* q, uint16_t val)
{
    *((uint16_t*)&q->used->ring[q->num]) = val;
}

void virtio_set_queue_max_merge_len_split(struct virtio_dev* dev, int q, int len)
{
    dev->split.queue[q].max_merge_len = len;
}

void virtio_set_queue_max_merge_len_packed(struct virtio_dev* dev, int q, int len)
{
    dev->packed.queue[q].max_merge_len = len;
}

/*
 * virtio_process_queue : process all the requests in the specific split queue
 * dev: virtio device structure pointer
 * qidx: queue index to be processed
 * fd: disk file descriptor
 */
void virtio_process_queue_split(struct virtio_dev* dev, uint32_t qidx)
{
    struct virtq* q = &dev->split.queue[qidx];

    if (!q->ready)
        return;

    if (dev->ops->acquire_queue)
        dev->ops->acquire_queue(dev, qidx);

    while (q->last_avail_idx != q->avail->idx)
    {
        /* Make sure following loads happens after loading q->avail->idx */
        if (virtio_process_one_split(dev, qidx) < 0)
            break;
        if (q->last_avail_idx == le16toh(q->avail->idx))
            virtio_set_avail_event(q, q->avail->idx);
    }

    if (dev->ops->release_queue)
        dev->ops->release_queue(dev, qidx);
}

/*
 * virtio_process_queue : process all the requests in the specific packed queue
 * dev: virtio device structure pointer
 * qidx: queue index to be processed
 * fd: disk file descriptor
 */
void virtio_process_queue_packed(struct virtio_dev* dev, uint32_t qidx)
{
    struct virtq_packed* q = &dev->packed.queue[qidx];

    if (!q->ready)
        return;

    if (dev->ops->acquire_queue)
        dev->ops->acquire_queue(dev, qidx);

    // Have some loop that keeps going until we hit a desc that's not available
    while (packed_desc_is_avail(q))
    {
        // Need to process desc here
        // Possible make some process_one_packed
        // Question is what else do I include in this statement
        if (virtio_process_one_packed(dev, qidx) < 0)
            break;
    }

    if (dev->ops->release_queue)
        dev->ops->release_queue(dev, qidx);
}

/*
 * virtio_process_queue : process all the requests in the specific queue
 * dev: virtio device structure pointer
 * qidx: queue index to be processed
 * fd: disk file descriptor
 */
void virtio_process_queue(struct virtio_dev* dev, uint32_t qidx)
{
    packed_ring ? virtio_process_queue_packed(dev, qidx) :
                  virtio_process_queue_split(dev, qidx);
}