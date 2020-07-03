#include <atomic.h>
#include <string.h>

#include "pthread_impl.h"

#include <lkl/virtio.h>

#include "enclave/enclave_util.h"
#include "enclave/lthread.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/ticketlock.h"
#include "enclave/vio_enclave_event_channel.h"

#include "openenclave/corelibc/oemalloc.h"

static struct ticketlock** evt_chn_lock;

/* Tasks monitoring event channels */
struct lthread** vio_tasks = NULL;

/* Event channel configuration */
static enc_dev_config_t* _enc_dev_config = NULL;
static bool _event_channel_initialized = false;
static uint8_t _evt_channel_num;

/*
 * Function to check whether virtio event channel task should stop or not
 */
static inline uint8_t vio_shutdown_requested(void)
{
    return lthread_should_stop();
}

/*
 * Function callback to set the thread state before yeilding the task
 */
static inline void set_thread_state(void* lth)
{
    struct lthread* lt = lth;
    /* set the sleep attribute to signify sleeping state */
    lt->attr.state &= CLEARBIT(LT_ST_READY);
    lt->attr.state |= BIT(LT_ST_SLEEPING);
}

/*
 * Function to yeild the virtio event channel task
 */
static inline void vio_wait_for_host_event(
    uint8_t dev_id,
    evt_t* evt_chn,
    evt_t val)
{
    struct lthread* lt = vio_tasks[dev_id];

    /* return if the event channel was signaled */
    if ((__atomic_load_n(evt_chn, __ATOMIC_SEQ_CST) != val) ||
        vio_shutdown_requested())
        return;
    /* release cpu for other tasks */
    _lthread_yield_cb(lt, set_thread_state, lt);
}

/*
 * Function to check whether sleeping event channel task needs wake up or not
 */
static inline int vio_signal_evt_channel(uint8_t dev_id)
{
    enc_evt_channel_t* evt_channel = _enc_dev_config[dev_id].enc_evt_chn;
    evt_t* processed = &_enc_dev_config[dev_id].evt_processed;
    evt_t* evt_chn = &evt_channel->enclave_evt_channel;

    evt_t cur = __atomic_load_n(evt_chn, __ATOMIC_SEQ_CST);

    struct lthread* lt = vio_tasks[dev_id];
    int state = __atomic_load_n(&lt->attr.state, __ATOMIC_SEQ_CST);

    if ((cur & 1) && (cur > (*processed + 1)) && (state & BIT(LT_ST_SLEEPING)))
        return 1;
    return 0;
}

/*
 * Function to spin the enclave device event handler. This function is
 * is used by each device thread which monitors the host device event
 * for processing
 */
static void vio_enclave_process_host_event(uint8_t* param)
{
    uint8_t dev_id = *param;

    /* release memory after extracting dev_id */
    oe_free(param);

    enc_evt_channel_t* evt_channel = _enc_dev_config[dev_id].enc_evt_chn;
    evt_t* evt_processed = &_enc_dev_config[dev_id].evt_processed;
    evt_t* evt_chn = &evt_channel->enclave_evt_channel;
    evt_t cur = 0, new = 0;

    for (;;)
    {
        new = cur;
        while ((cur = __atomic_load_n(evt_chn, __ATOMIC_SEQ_CST)) == new)
        {
            new = cur + 1;
            if (__atomic_compare_exchange_n(
                    evt_chn,
                    &cur,
                    new,
                    true,
                    __ATOMIC_SEQ_CST,
                    __ATOMIC_SEQ_CST))
            {
                vio_wait_for_host_event(dev_id, evt_chn, new);
                SGXLKL_ASSERT(new & 1);

                /* clear the waiting bit to process all the request queued up */
                cur = __atomic_add_fetch(evt_chn, -1, __ATOMIC_SEQ_CST);
                break;
            }
        }

        /* ignore the event if it is already seen */
        if (cur > *evt_processed)
        {
            lkl_virtio_deliver_irq(dev_id);
            *evt_processed = cur;
        }

        if (vio_shutdown_requested())
            break;
    }
    lthread_detach2(lthread_self());
    lthread_exit(0);
}

/*
 * Function to initialize enclave event handler
 */
void initialize_enclave_event_channel(
    enc_dev_config_t* enc_dev_config,
    size_t evt_channel_num)
{
    uint8_t* dev_id = NULL;
    _evt_channel_num = evt_channel_num;

    evt_chn_lock = (struct ticketlock**)oe_calloc(
        evt_channel_num, sizeof(struct ticketlock*));

    vio_tasks =
        (struct lthread**)oe_calloc(evt_channel_num, sizeof(struct lthread*));

    _enc_dev_config = enc_dev_config;
    for (int i = 0; i < evt_channel_num; i++)
    {
        evt_chn_lock[i] =
            (struct ticketlock*)oe_calloc(1, sizeof(struct ticketlock));
        memset(evt_chn_lock[i], 0, sizeof(struct ticketlock));

        dev_id = (uint8_t*)oe_calloc(1, sizeof(uint8_t));
        *dev_id = enc_dev_config[i].dev_id;

        struct lthread* lt = NULL;
        if (lthread_create(
                &lt, NULL, vio_enclave_process_host_event, (void*)dev_id) != 0)
        {
            oe_free(vio_tasks);
            sgxlkl_fail("Failed to create lthread for event channel\n");
        }
        vio_tasks[i] = lt;
    }
    /* Mark event channel as initialized to be picked up by scheduler */
    _event_channel_initialized = true;
}

/*
 * Function to notify host device event handler for the processing of events
 */
void vio_enclave_notify_enclave_event(uint8_t dev_id, uint32_t qidx)
{
    enc_evt_channel_t* evt_chn = _enc_dev_config[dev_id].enc_evt_chn;
    uint32_t* qidx_p = evt_chn->qidx_p;

    evt_t cur =
        __atomic_fetch_add(evt_chn->host_evt_channel, 2, __ATOMIC_SEQ_CST);

    *qidx_p = qidx;

    /* host task sleeping, wake up (ocall) */
    if (cur & 1)
        sgxlkl_host_device_request(dev_id);
}

/*
 * Function to wakeup the sleeping event channel task
 */
int vio_enclave_wakeup_event_channel(void)
{
    int ret = 0;

    /* Event channel processing not available */
    if (!_event_channel_initialized)
        return 0;

    /* Schedule picks up the available event channel processing */
    for (uint8_t dev_id = 0; dev_id < _evt_channel_num; dev_id++)
    {
        if (ticket_trylock(evt_chn_lock[dev_id]) == EBUSY)
            continue;

        int rc = vio_signal_evt_channel(dev_id);
        if (rc || vio_shutdown_requested())
            lthread_wakeup(vio_tasks[dev_id]);
        ret |= rc;
        ticket_unlock(evt_chn_lock[dev_id]);
    }

    return ret;
}
