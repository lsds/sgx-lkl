#define _GNU_SOURCE

/* Below code is reused from src/lkl/virtio_net.c and modified
 * to support the virtio net device in host */

/*
 * POSIX file descriptor based virtual network interface feature for
 * LKL Copyright (c) 2015,2016 Ryo Nakamura, Hajime Tazaki
 *
 * Copyright 2016, 2017, 2018 Imperial College London
 *
 * Author: Ryo Nakamura <upa@wide.ad.jp>
 *         Hajime Tazaki <thehajime@gmail.com>
 *         Octavian Purdila <octavian.purdila@intel.com>
 *
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <host/host_state.h>
#include <host/sgxlkl_util.h>
#include <host/vio_host_event_channel.h>
#include <host/virtio_debug.h>
#include <host/virtio_netdev.h>
#include <poll.h>
#include <shared/env.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>

/* We always have 2 queues on a netdev: one for tx, one for rx. */
#define RX_QUEUE_IDX 0
#define TX_QUEUE_IDX 1

#define MAX_NET_DEVS 16
#define NUM_QUEUES (TX_QUEUE_IDX + 1)
#define QUEUE_DEPTH 128

#define DEV_NET_POLL_RX 1
#define DEV_NET_POLL_TX 2
#define DEV_NET_POLL_HUP 4

struct netdev_fd
{
    /* file-descriptor based device */
    int fd;
    /* control pipe */
    int pipe[2];
};

struct virtio_net_dev
{
    struct virtio_dev dev;
    struct virtio_net_config config;
    pthread_mutex_t** queue_locks;
    pthread_t poll_tid;
    /* file descriptor used for virtio net device */
    struct netdev_fd ndev_fd;
};

#if DEBUG && VIRTIO_TEST_HOOK
static uint64_t virtio_net_tx_cnt;
static uint64_t virtio_net_rx_cnt;
#endif

/* local variables to hold the netdev instance */
struct virtio_net_dev* registered_devs[MAX_NET_DEVS];
static uint8_t registered_dev_idx = 0;
static uint8_t has_vnet_hdr;

/* In SGXLKL device id is enumerated in the following order
 * 1. Block devices (root device + additional devices)
 * 2. Network devices (multiple network interface)
 * 3. Console device
 *
 * Network base id stores total no of disks and it becomes the base id for
 * network device. For instance if the total disks count is 2 then dev_id
 * for virtio net dev will start from 2.
 * In order to fetch the net dev id, _netdev_base_id should be substracted
 * from the dev_id provided from virtio dev structure */
static uint8_t _netdev_id;
static uint8_t _netdev_base_id;

static inline uint8_t get_netdev_id(uint8_t dev_id)
{
    return (dev_id - _netdev_base_id);
}

/* Function to get the virtio netdev instance */
static inline struct virtio_net_dev* get_virtio_netdev_instance(
    uint8_t netdev_id)
{
    struct virtio_net_dev* ndev_instance = registered_devs[netdev_id];
    assert(ndev_instance != NULL);
    return ndev_instance;
}

/*
 * Function to get netdev_fd instance associated to virtio netdev instance
 */
static inline struct netdev_fd* get_netdev_fd_instance(uint8_t netdev_id)
{
    struct virtio_net_dev* ndev_instance =
        get_virtio_netdev_instance(netdev_id);
    return &ndev_instance->ndev_fd;
}

/*
 * Function to register net device & hold reference of newly allocated device
 */
static int register_net_device(struct virtio_net_dev* net_dev, int fd)
{
    /* hold the allocated virtio netdevice */
    registered_devs[registered_dev_idx] = net_dev;
    struct netdev_fd* nd_fd = &registered_devs[registered_dev_idx]->ndev_fd;

    nd_fd->fd = fd;

    int r = pipe(nd_fd->pipe);
    if (r < 0)
    {
        sgxlkl_host_fail("%s: pipe call failed: %s", __func__, strerror(-r));
        return 1;
    }

    r = fcntl(nd_fd->pipe[0], F_SETFL, O_NONBLOCK);
    if (r < 0)
    {
        sgxlkl_host_fail("%s: fnctl call failed: %s", __func__, strerror(-r));
        close(nd_fd->pipe[0]);
        close(nd_fd->pipe[1]);
        return 1;
    }
    return 0;
}

/*
 * Function to poll the pipes to check the reception or transmission
 */
static int virtio_net_fd_net_poll(uint8_t netdev_id)
{
    int ret;
    struct netdev_fd* nd_fd = get_netdev_fd_instance(netdev_id);

    struct pollfd pfds[2] = {
        {
            .fd = nd_fd->fd,
            .events = POLLIN | POLLOUT | POLLPRI,
        },
        {
            .fd = nd_fd->pipe[0],
            .events = POLLIN,
        },
    };

    do
    {
        ret = poll(pfds, 2, -1);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0)
    {
        sgxlkl_host_fail("%s: poll fd failed: %s", __func__, strerror(errno));
        return 0;
    }

    if (pfds[1].revents & (POLLHUP | POLLNVAL))
        return DEV_NET_POLL_HUP;

    if (pfds[1].revents & POLLIN)
    {
        char tmp[PIPE_BUF];
        ret = read(nd_fd->pipe[0], tmp, PIPE_BUF);
        if (ret == 0)
            return DEV_NET_POLL_HUP;
        if (ret < 0)
        {
            sgxlkl_host_err(
                "%s: read from fd (%d) failed: %s",
                __func__,
                nd_fd->pipe[0],
                strerror(errno));
        }
    }

    ret = 0;
    if (pfds[0].revents & (POLLIN | POLLPRI))
    {
        ret |= DEV_NET_POLL_RX;
    }

    if (pfds[0].revents & POLLOUT)
    {
        ret |= DEV_NET_POLL_TX;
    }
    return ret;
}

/*
 * Function to close the pipe used for tx & rx
 */
static void virtio_net_fd_net_poll_hup(uint8_t netdev_id)
{
    struct netdev_fd* nd_fd = get_netdev_fd_instance(netdev_id);
    close(nd_fd->pipe[0]);
    close(nd_fd->pipe[1]);
}

/*
 * Function to close the net device
 */
static void virtio_net_fd_net_free(uint8_t netdev_id)
{
    struct netdev_fd* nd_fd = get_netdev_fd_instance(netdev_id);
    close(nd_fd->fd);
}

/*
 * Function to perform tx operation
 */
static int virtio_net_fd_net_tx(uint8_t netdev_id, struct iovec* iov, int cnt)
{
    struct netdev_fd* nd_fd = get_netdev_fd_instance(netdev_id);
    int ret = 0;
    do
    {
        ret = writev(nd_fd->fd, iov, cnt);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0)
    {
        char tmp;

        switch (errno)
        {
            case EAGAIN:
            {
                int pipe_ret = write(nd_fd->pipe[1], &tmp, 1);

                // Check if there was an error but the fd has not been closed
                if (pipe_ret <= 0 && errno != EBADF)
                    sgxlkl_host_fail(
                        "%s: write to fd pipe failed: fd=%i ret=%i errno=%i %s",
                        __func__,
                        nd_fd->pipe[1],
                        pipe_ret,
                        errno,
                        strerror(errno));
                break;
            }

            // Check if the fd has been closed and return error
            case EBADF:
                break;

            default:
                sgxlkl_host_fail(
                    "%s: write failed: fd=%i ret=%i errno=%i %s",
                    __func__,
                    nd_fd->fd,
                    ret,
                    errno,
                    strerror(errno));
        }
    }
    return ret;
}

/*
 * Function to perform rx operation
 */
static int virtio_net_fd_net_rx(uint8_t netdev_id, struct iovec* iov, int cnt)
{
    int ret = 0;
    struct netdev_fd* nd_fd = get_netdev_fd_instance(netdev_id);

    do
    {
        ret = readv(nd_fd->fd, iov, cnt);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0)
    {
        char tmp;

        switch (errno)
        {
            case EAGAIN:
            {
                int pipe_ret = write(nd_fd->pipe[1], &tmp, 1);

                // Check if there was an error but the fd has not been closed
                if (pipe_ret < 0 && errno != EBADF)
                    sgxlkl_host_fail(
                        "%s: write to fd pipe failed: fd=%i ret=%i errno=%i "
                        "%s\n",
                        __func__,
                        nd_fd->pipe[1],
                        pipe_ret,
                        errno,
                        strerror(errno));
                break;
            }

            // Check if the fd has been closed and return error
            case EBADF:
                break;

            default:
                sgxlkl_host_info(
                    "%s: read failed: fd=%d ret=%d errno=%i %s\n",
                    __func__,
                    nd_fd->fd,
                    ret,
                    errno,
                    strerror(errno));
        }
    }
    return ret;
}

/*
 * virtio callback function
 */
static int net_check_features(struct virtio_dev* dev)
{
    if (dev->driver_features == dev->device_features)
        return 0;

    return -EINVAL;
}

/*
 * virtio callback function to acquire queue lock
 */
static void net_acquire_queue(struct virtio_dev* dev, int queue_idx)
{
    int netdev_id = get_netdev_id(dev->vendor_id);
    struct virtio_net_dev* netdev = get_virtio_netdev_instance(netdev_id);
    assert(netdev_id >= 0);
    pthread_mutex_lock(netdev->queue_locks[queue_idx]);
}

/*
 * virtio callback function to release queue lock
 */
static void net_release_queue(struct virtio_dev* dev, int queue_idx)
{
    int netdev_id = get_netdev_id(dev->vendor_id);
    struct virtio_net_dev* netdev = get_virtio_netdev_instance(netdev_id);
    assert(netdev_id >= 0);
    pthread_mutex_unlock(netdev->queue_locks[queue_idx]);
}

/*
 * Virtio callback function to process the virtio request
 */
static int net_enqueue(struct virtio_dev* dev, int q, struct virtio_req* req)
{
    struct virtio_net_hdr_v1* header;
    struct iovec* iov;
    int ret;

    int netdev_id = get_netdev_id(dev->vendor_id);
    assert(netdev_id >= 0);

    header = req->buf[0].iov_base;

    /*
     * The backend device does not expect a vnet_hdr so adjust buf
     * accordingly. (We make adjustment to req->buf so it can be used
     * directly for the tx/rx call but remember to undo the change after the
     * call.  Note that it's ok to pass iov with entry's len==0.  The caller
     * will skip to the next entry correctly.
     */
    if (!has_vnet_hdr)
    {
        req->buf[0].iov_base += sizeof(*header);
        req->buf[0].iov_len -= sizeof(*header);
    }
    iov = req->buf;

    /* Pick which virtqueue to send the buffer(s) to */
    if (q == TX_QUEUE_IDX)
    {
        ret = virtio_net_fd_net_tx(netdev_id, iov, req->buf_count);
        if (ret < 0)
            return -1;
    }
    else if (q == RX_QUEUE_IDX)
    {
        int i, len;

        ret = virtio_net_fd_net_rx(netdev_id, iov, req->buf_count);
        if (ret < 0)
            return -1;
        if (has_vnet_hdr)
        {
            /*
             * If the number of bytes returned exactly matches the
             * total space in the iov then there is a good chance we
             * did not supply a large enough buffer for the whole
             * pkt, i.e., pkt has been truncated.  This is only
             * likely to happen under mergeable RX buffer mode.
             */
            if (req->total_len == (unsigned int)ret)
                sgxlkl_host_fail("PKT is likely truncated! len=%d\n", ret);
        }
        else
        {
            header->flags = 0;
            header->gso_type = VIRTIO_NET_HDR_GSO_NONE;
        }
        /*
         * Have to compute how many descriptors we've consumed (really
         * only matters to the the mergeable RX mode) and return it
         * through "num_buffers".
         */
        for (i = 0, len = ret; len > 0; i++)
            len -= req->buf[i].iov_len;
        header->num_buffers = i;

        if (dev->device_features & BIT(VIRTIO_NET_F_GUEST_CSUM))
            header->flags |= VIRTIO_NET_HDR_F_DATA_VALID;
    }
    else
    {
        sgxlkl_host_fail("tried to push on non-existent queue");
        return -1;
    }

    if (!has_vnet_hdr)
    {
        /* Undo the adjustment */
        req->buf[0].iov_base -= sizeof(*header);
        req->buf[0].iov_len += sizeof(*header);
        ret += sizeof(struct virtio_net_hdr_v1);
    }
    virtio_req_complete(req, ret);
    return 0;
}

/*
 * Function to free the queue locks
 */
static void free_queue_locks(pthread_mutex_t** queues, int num_queues)
{
    if (!queues)
        return;

    for (int i = 0; i < num_queues; i++)
        free(queues[i]);
    free(queues);
}

/*
 * Function to initialize the queue locks
 */
static pthread_mutex_t** init_queue_locks(int num_queues)
{
    pthread_mutex_t** mtx =
        (pthread_mutex_t**)calloc(num_queues, sizeof(pthread_mutex_t*));

    if (mtx)
    {
        memset(mtx, 0, (sizeof(pthread_mutex_t*) * num_queues));
        for (int i = 0; i < num_queues; i++)
        {
            mtx[i] = (pthread_mutex_t*)calloc(1, sizeof(pthread_mutex_t));
            if (!mtx[i])
            {
                free_queue_locks(mtx, i);
                return NULL;
            }
        }
    }
    return mtx;
}

static struct virtio_dev_ops host_net_ops = {
    .check_features = net_check_features,
    .enqueue = net_enqueue,
    .acquire_queue = net_acquire_queue,
    .release_queue = net_release_queue,
};

/*
 * Function to poll for the event on the tap interface
 */
void* poll_thread(void* arg)
{
    int netdev_id = *(int*)arg;
    struct virtio_net_dev* dev = get_virtio_netdev_instance(netdev_id);
    free(arg);
    do
    {
        int ret = virtio_net_fd_net_poll(netdev_id);
        if (ret < 0)
        {
            sgxlkl_host_info("virtio net poll error: %d\n", ret);
            continue;
        }
        /* synchronization is handled in virtio_process_queue */
        if (ret & DEV_NET_POLL_HUP)
            break;
        if (ret & DEV_NET_POLL_RX)
        {
            virtio_process_queue(&dev->dev, RX_QUEUE_IDX);
#if DEBUG && VIRTIO_TEST_HOOK
            uint64_t vio_req_cnt = virtio_debug_net_rx_get_ring_count();
            if ((vio_req_cnt) && !(virtio_net_rx_cnt++ % vio_req_cnt))
                virtio_debug_set_evt_chn_state(true);
#endif
        }
        if (ret & DEV_NET_POLL_TX)
        {
            virtio_process_queue(&dev->dev, TX_QUEUE_IDX);
        }
    } while (1);
    return NULL;
}

/*
 * Function to initialize the net device based on the user config. This
 * function allocates the memory for virtio device & virtio ring buffer.
 * The shared memory is shared between host & enclave.
 */
int netdev_init(sgxlkl_host_state_t* host_state)
{
    void* netdev_vq_mem = NULL;
    struct virtio_net_dev* net_dev = NULL;
    char mac[6];
    // Generate a completely random MAC address
    size_t b = 0;
    while (b < sizeof(mac))
    {
        ssize_t ret = getrandom(&mac[b], sizeof(mac) - b, GRND_RANDOM);
        if (ret < 0)
        {
            sgxlkl_host_fail(
                "%s: get random MAC address failed: %s\n",
                __func__,
                strerror(errno));
            return -1;
        }
        b += ret;
    }
    // Set the locally administered bit:
    mac[0] |= 2;
    // Clear the multicast bit (give a unicast MAC address)
    mac[0] &= 0xfe;

    size_t host_netdev_size = next_pow2(sizeof(struct virtio_net_dev));
    size_t netdev_vq_size = NUM_QUEUES * sizeof(struct virtq);
    netdev_vq_size = next_pow2(netdev_vq_size);

    if (!_netdev_id)
    {
        /* Net devices get the IDs following disks (root + mounts) */
        _netdev_base_id = _netdev_id = host_state->num_disks;
    }

    /* Allocate memory for net device */
    net_dev = mmap(
        0,
        host_netdev_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0);

    if (!net_dev)
    {
        sgxlkl_host_fail("Host net device mem alloc failed\n");
        return -1;
    }

    /* Allocate memory for virtio queue */
    netdev_vq_mem = mmap(
        0,
        netdev_vq_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0);

    if (!netdev_vq_mem)
    {
        sgxlkl_host_fail("Host net device virtio queue mem alloc failed\n");
        return -1;
    }

    net_dev->dev.queue = netdev_vq_mem;
    memset(net_dev->dev.queue, 0, netdev_vq_size);

    /* assign the queue depth to each virt queue */
    for (int i = 0; i < NUM_QUEUES; i++)
        net_dev->dev.queue[i].num_max = QUEUE_DEPTH;

    /* set net device feature */
    net_dev->dev.device_id = VIRTIO_ID_NET;
    net_dev->dev.vendor_id = _netdev_id++;
    net_dev->dev.device_features |= BIT(VIRTIO_NET_F_MAC);
    net_dev->dev.device_features |=
        BIT(VIRTIO_F_VERSION_1) | BIT(VIRTIO_RING_F_EVENT_IDX);

    if (host_state->enclave_config.swiotlb)
        net_dev->dev.device_features |= BIT(VIRTIO_F_IOMMU_PLATFORM);

    if (host_state->config.tap_offload)
    {
        has_vnet_hdr = 1;
        net_dev->dev.device_features |=
            BIT(VIRTIO_NET_F_CSUM) | BIT(VIRTIO_NET_F_GUEST_CSUM) |
            BIT(VIRTIO_NET_F_HOST_TSO4) | BIT(VIRTIO_NET_F_GUEST_TSO4) |
            BIT(VIRTIO_NET_F_HOST_TSO6) | BIT(VIRTIO_NET_F_GUEST_TSO6) |
            BIT(VIRTIO_NET_F_MRG_RXBUF);
    }

    net_dev->dev.device_features |= BIT(VIRTIO_NET_F_MAC);
    memcpy(net_dev->config.mac, mac, ETH_ALEN);

    net_dev->dev.config_data = &net_dev->config;
    net_dev->dev.config_len = sizeof(net_dev->config);
    net_dev->dev.ops = &host_net_ops;
    net_dev->queue_locks = init_queue_locks(NUM_QUEUES);

    /*
     * We may receive upto 64KB TSO packet so collect as many descriptors as
     * there are available up to 64KB in total len.
     */
    if (net_dev->dev.device_features & BIT(VIRTIO_NET_F_MRG_RXBUF))
        virtio_set_queue_max_merge_len(&net_dev->dev, RX_QUEUE_IDX, 65536);

    /* Register the netdev fd */
    register_net_device(net_dev, host_state->net_fd);

    int* netdev_id = (int*)malloc(sizeof(int));
    assert(netdev_id != NULL);

    *netdev_id = registered_dev_idx;
    pthread_create(&net_dev->poll_tid, NULL, poll_thread, (void*)netdev_id);

    if (net_dev->poll_tid == 0)
    {
        sgxlkl_host_fail("Failed to start the network poll task\n");
        return -1;
    }
    pthread_setname_np(net_dev->poll_tid, "HOST_NETDEVICE");

    /* Hold memory allocated for virtio netdev to be used in enclave.
     * currently one net device is supported, at somepoint when multiple devices
     * are supported then virtio_net_dev_mem should hold array of devices */
    host_state->shared_memory.virtio_net_dev_mem = &net_dev->dev;

    /* return netdev index */
    return registered_dev_idx++;
}

/*
 * network device host task to process the request from guest.
 */
void* netdev_task(void* arg)
{
    host_dev_config_t* cfg = arg;

    int netdev_id = get_netdev_id(cfg->dev_id);
    host_evt_channel_t* evt_chn = cfg->host_evt_chn;
    struct virtio_net_dev* netdev = get_virtio_netdev_instance(netdev_id);

    for (;;)
    {
        vio_host_process_enclave_event(cfg->dev_id, -1);
        virtio_process_queue(&netdev->dev, evt_chn->qidx_p);
#if DEBUG && VIRTIO_TEST_HOOK
        uint64_t vio_req_cnt = virtio_debug_net_tx_get_ring_count();
        if ((vio_req_cnt) && !(virtio_net_tx_cnt++ % vio_req_cnt))
            virtio_debug_set_evt_chn_state(true);
#endif
    }
}

/*
 * Function to stop the polling thread for stopping the network interface
 */
void net_dev_remove(uint8_t netdev_id)
{
    struct virtio_net_dev* net_dev = get_virtio_netdev_instance(netdev_id);
    virtio_net_fd_net_poll_hup(netdev_id);
    virtio_net_fd_net_free(netdev_id);
    pthread_join(net_dev->poll_tid, NULL);
}
