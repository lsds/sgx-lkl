#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <host/host_state.h>
#include <host/sgxlkl_util.h>
#include <host/vio_host_event_channel.h>
#include <host/virtio_console.h>
#include <poll.h>
#include <shared/env.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* two queue for one console port */
#define NUM_QUEUES 2
#define QUEUE_DEPTH 32

#define PIPE_BUF 4096

/* time in milliseconds */
#define WAIT_FOR_EVENT_TIMEOUT 10

/* Identifier for signaling the appropiate events */
#define DEV_CONSOLE_WRITE 1
#define DEV_CONSOLE_HUP 2

/* Queue IDs for receiving and sending queue */
#define RX_QUEUE_ID 0
#define TX_QUEUE_ID 1

/* Virtio console device structure */
struct virtio_console_dev
{
    int in_console_fd;
    int out_console_fd;
    struct virtio_dev dev;
    pthread_t monitor_tid;
    pthread_mutex_t** qlocks;
};

/* Local variable to hold the settings locally */
static host_dev_config_t* _cfg = NULL;
static struct virtio_console_dev* _console_dev = NULL;

/*
 * Function to return the console backend device instance
 */
static inline struct virtio_console_dev* get_console_dev_instance()
{
    return _console_dev;
}

/*
 * Function to poll for the input from console input device
 */
static int poll_console_for_input(int poll_fd)
{
    int ret = 0;
    struct pollfd pfd = {
        .fd = poll_fd,
        .events = POLLIN | POLLPRI,
    };

    do
    {
        ret = poll(&pfd, 1, -1);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0)
    {
        sgxlkl_host_fail("%s: poll fd failed: %d\n", __func__, errno);
        return 0;
    }

    if (pfd.revents & (POLLHUP | POLLNVAL))
        return DEV_CONSOLE_HUP;

    ret = 0;
    if (pfd.revents & (POLLIN | POLLPRI))
        ret |= DEV_CONSOLE_WRITE;

    return ret;
}

/*
 * Function to poll for an event from standard input stream
 */
void* monitor_console_input(void* cons_dev)
{
    struct virtio_console_dev* vcd = cons_dev;
    struct virtio_dev* dev = &vcd->dev;
    do
    {
        int ret = poll_console_for_input(vcd->in_console_fd);
        if (ret < 0)
        {
            sgxlkl_host_info("virtio net poll error: %d\n", ret);
            continue;
        }

        if (ret & DEV_CONSOLE_HUP)
            break;

        if (ret & DEV_CONSOLE_WRITE)
        {
            virtio_process_queue(dev, RX_QUEUE_ID);
        }
    } while (1);
    return NULL;
}

/*
 * Function to free the locks created for protecting queues
 */
static void free_qlocks(pthread_mutex_t** locks, int qnum)
{
    if (!locks)
        return;

    for (int i = 0; i < qnum; i++)
        free(locks[i]);
    free(locks);
}

/*
 * Function to initialize the queue locks
 */
static pthread_mutex_t** init_queue_locks(int qnum)
{
    pthread_mutex_t** mtxlock =
        (pthread_mutex_t**)calloc(qnum, sizeof(pthread_mutex_t*));

    if (mtxlock)
    {
        memset(mtxlock, 0, (sizeof(pthread_mutex_t*) * qnum));
        for (int i = 0; i < qnum; i++)
        {
            mtxlock[i] = (pthread_mutex_t*)calloc(1, sizeof(pthread_mutex_t));
            if (!mtxlock[i])
            {
                free_qlocks(mtxlock, i);
                return NULL;
            }
        }
    }
    return mtxlock;
}

/*
 * Virtio callback function to acquire the lock before processing the request
 */
static void console_acquire_queue(struct virtio_dev* dev, int queue_idx)
{
    struct virtio_console_dev* vcd = get_console_dev_instance();
    assert(vcd != NULL);
    pthread_mutex_lock(vcd->qlocks[queue_idx]);
}

/*
 * Virtio callback function to release the lock once the processing is completed
 */
static void console_release_queue(struct virtio_dev* dev, int queue_idx)
{
    struct virtio_console_dev* vcd = get_console_dev_instance();
    assert(vcd != NULL);
    pthread_mutex_unlock(vcd->qlocks[queue_idx]);
}

/*
 * Function to process the virtio request
 */
static int console_enqueue(
    struct virtio_dev* dev,
    int q,
    struct virtio_req* req)
{
    ssize_t ret = 0;
    struct virtio_console_dev* vcd = get_console_dev_instance();
    struct iovec* iov = req->buf;

    if (q == RX_QUEUE_ID)
    {
        do
        {
            ret = readv(vcd->in_console_fd, iov, req->buf_count);
        } while (ret == -1 && errno == EINTR);
    }
    else
    {
        do
        {
            ret = writev(vcd->out_console_fd, iov, req->buf_count);
        } while (ret == -1 && errno == EINTR);
    }

    ssize_t bytes = ret <= 0 ? 0 : ret;
    virtio_req_complete(req, bytes);

    return ret >= 0 ? 0 : -1;
}

/*
 * Function to check the features supported
 */
static int console_check_features(struct virtio_dev* dev)
{
    if (dev->driver_features == dev->device_features)
        return 0;

    return -EINVAL;
}

static struct virtio_dev_ops host_console_ops = {
    .check_features = console_check_features,
    .enqueue = console_enqueue,
    .acquire_queue = console_acquire_queue,
    .release_queue = console_release_queue,
};

/*
 * Function to initialize the console device based on the user config
 * This function allocates the memory for virtio device & virtio ring buffer.
 * The shared memory is shared between host & enclave
 */
int virtio_console_init(sgxlkl_host_state_t* host_state, host_dev_config_t* cfg)
{
    void* console_vq_mem = NULL;

    size_t host_console_size = next_pow2(sizeof(struct virtio_console_dev));
    size_t console_vq_size;

    if (!packed_ring)
        console_vq_size = NUM_QUEUES * sizeof(struct virtq);
    else
        console_vq_size = NUM_QUEUES * sizeof(struct virtq_packed);

    console_vq_size = next_pow2(console_vq_size);

    /* Console host device configuration */
    _cfg = cfg;

    /* Allocate memory for console device */
    _console_dev = mmap(
        0,
        host_console_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0);

    if (!_console_dev)
    {
        sgxlkl_host_fail("Host console device mem alloc failed\n");
        return -1;
    }

    /* Allocate memory for virtio queue */
    console_vq_mem = mmap(
        0,
        console_vq_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0);

    if (!console_vq_mem)
    {
        sgxlkl_host_fail("Host console device virtio queue mem alloc failed\n");
        return -1;
    }

    _console_dev->in_console_fd = STDIN_FILENO;
    _console_dev->out_console_fd = STDOUT_FILENO;
    struct virtio_dev* dev = &_console_dev->dev;

    if (!packed_ring)
    {
        dev->split.queue = console_vq_mem;
        memset(dev->split.queue, 0, console_vq_size);
    }
    else
    {
        dev->packed.queue = console_vq_mem;
        memset(dev->packed.queue, 0, console_vq_size);
    }

    /* assign the queue depth to each virt queue */
    for (int i = 0; i < NUM_QUEUES; i++)
    {
        if (!packed_ring)
        {
            dev->split.queue[i].num_max = QUEUE_DEPTH;
        }
        else
        {
            dev->packed.queue[i].num_max = QUEUE_DEPTH;
            dev->packed.queue[i].device_wrap_counter = 1;
            dev->packed.queue[i].driver_wrap_counter = 1;
        }
    }

    /* set console device feature */
    dev->device_id = VIRTIO_ID_CONSOLE;
    dev->vendor_id = _cfg->dev_id;
    dev->device_features =
        BIT(VIRTIO_F_VERSION_1) | BIT(VIRTIO_RING_F_EVENT_IDX);

    dev->device_features |= BIT(VIRTIO_CONSOLE_F_SIZE);

    if (host_state->enclave_config.mode != SW_DEBUG_MODE)
        dev->device_features |= BIT(VIRTIO_F_IOMMU_PLATFORM);

    if (packed_ring)
        dev->device_features |= BIT(VIRTIO_F_RING_PACKED);

    dev->ops = &host_console_ops;

    _console_dev->qlocks = init_queue_locks(NUM_QUEUES);

    /* Start the console monitor thread for monitoring the input */
    pthread_create(
        &_console_dev->monitor_tid, NULL, monitor_console_input, _console_dev);

    /* Check the polling thread spawning status */
    if (_console_dev->monitor_tid == 0)
        sgxlkl_host_fail("Failed to start the host console poll task\n");

    host_state->shared_memory.virtio_console_mem = &_console_dev->dev;

    return 0;
}

/*
 * Host console task for monitoring the virtio events from host
 * and processing the request
 */
void* console_task(void* arg)
{
    int timeout_ms = WAIT_FOR_EVENT_TIMEOUT;
    struct virtio_dev* dev = &_console_dev->dev;

    pthread_mutex_init(&(_cfg->lock), NULL);
    pthread_cond_init(&(_cfg->cond), NULL);

    while (1)
    {
        vio_host_process_enclave_event(_cfg->dev_id, timeout_ms);

        if (vio_host_check_guest_shutdown_evt())
            continue;

        virtio_process_queue(dev, TX_QUEUE_ID);
    }
}
