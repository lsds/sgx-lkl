#include <assert.h>
#include <errno.h>
#include <host/sgxlkl_u.h>
#include <host/sgxlkl_util.h>
#include <host/vio_host_event_channel.h>
#include <host/virtio_debug.h>
#include <shared/sgxlkl_config.h>

#define LKL_SHUTDOWN_NOTIFICATION 1

static host_dev_config_t* _dev_cfg;
static uint8_t _evt_chn_num;

/* notifier to notify the host device task for the LKL shutdown event */
static _Atomic(int) sgxlkl_shutdown_notifier = 0;

extern void sgxlkl_signal_vio_event(void);

#if DEBUG && VIRTIO_TEST_HOOK
/* Function to block the device events to be delivered to guest */
static void pause_event_channel(void)
{
    while (virtio_debug_get_evt_chn_state())
        usleep(1000 * 10);
}
#endif // DEBUG && VIRTIO_TEST_HOOK

/*
 * Function to wait for an event to process request from guest
 */
static inline int _vio_host_wait_for_enclave_event(
    host_dev_config_t* cfg,
    evt_t* evt_chn,
    evt_t val,
    int timeout_ms)
{
    int rc = 0;
    struct timespec timeout, now;

    if (timeout_ms > 0)
    {
        clock_gettime(CLOCK_MONOTONIC, &now);
        timeout.tv_sec = now.tv_sec;
        timeout.tv_nsec = now.tv_nsec + (timeout_ms * 1000000UL);

        if (timeout.tv_nsec >= NSEC_PER_SECOND)
        {
            timeout.tv_sec += timeout.tv_nsec / NSEC_PER_SECOND;
            timeout.tv_nsec = timeout.tv_nsec % NSEC_PER_SECOND;
        }
    }

    if (__atomic_load_n(evt_chn, __ATOMIC_SEQ_CST) != val)
        return 0;

    if (timeout_ms > 0)
        rc = pthread_cond_timedwait(&cfg->cond, &cfg->lock, &timeout);
    else
        rc = pthread_cond_wait(&cfg->cond, &cfg->lock);

    if (rc != 0 && rc != ETIMEDOUT)
        sgxlkl_host_info("%s: id=%d (%d)\n", __func__, cfg->dev_id, rc);

    return 0;
}

/*
 * Function to initialize the device event handler
 */
void vio_host_initialize_device_cfg(
    host_dev_config_t* dev_cfg,
    uint8_t evt_channel_num)
{
    _dev_cfg = dev_cfg;
    _evt_chn_num = evt_channel_num;

    return;
}

/*
 * Function to signal host device event handler waiting for an event
 */
void sgxlkl_host_handle_device_request(uint8_t dev_id)
{
    host_dev_config_t* dev_config = &_dev_cfg[dev_id];
    pthread_cond_signal(&dev_config->cond);
    return;
}

/*
 * Function to wait for an host device access events from guest
 */
void vio_host_process_enclave_event(uint8_t dev_id, int timeout_ms)
{
    host_dev_config_t* dev_config = &_dev_cfg[dev_id];
    host_evt_channel_t* evt_chn = dev_config->host_evt_chn;
    evt_t* evt_processed = &dev_config->evt_processed;
    pthread_mutex_lock(&dev_config->lock);

    evt_t desired = *evt_processed + 1;
    assert((*evt_processed & 1) == 0);

    if (!__atomic_compare_exchange_n(
            &evt_chn->host_evt_channel,
            evt_processed,
            desired,
            true,
            __ATOMIC_SEQ_CST,
            __ATOMIC_SEQ_CST))
    {
        pthread_mutex_unlock(&dev_config->lock);
        return;
    }

    /* wait for an event */
    _vio_host_wait_for_enclave_event(
        dev_config, &evt_chn->host_evt_channel, desired, timeout_ms);
    assert(desired & 1);

    *evt_processed =
        __atomic_add_fetch(&evt_chn->host_evt_channel, -1, __ATOMIC_SEQ_CST);

    pthread_mutex_unlock(&dev_config->lock);
    return;
}

/*
 * Function to wake up the guest device event handler
 */
int vio_host_notify_host_event(uint8_t dev_id)
{
    host_dev_config_t* cfg = &_dev_cfg[dev_id];
    host_evt_channel_t* evt = cfg->host_evt_chn;

#if DEBUG && VIRTIO_TEST_HOOK
    /* pause event channel will stop sending the events to guest. Lack of event
     * will make guest idle and eventually all lthreads will move to sleep till
     * test framework sends an continue event to resume */
    pause_event_channel();
#endif
    evt_t cur =
        __atomic_add_fetch(evt->enclave_evt_channel, 2, __ATOMIC_SEQ_CST);

    /* wakeup sleeping ethread notifying an events */
    if (cur & 1)
        sgxlkl_signal_vio_event();
}

/*
 * Function to set shutdown evt for host device
 */
void vio_host_notify_guest_shutdown_evt()
{
    /* Set the flag for notifying host device task */
    sgxlkl_shutdown_notifier = LKL_SHUTDOWN_NOTIFICATION;
}

/*
 * Function to check whether guest notified shutdown evt
 */
int vio_host_check_guest_shutdown_evt()
{
    return sgxlkl_shutdown_notifier;
}

#if DEBUG && VIRTIO_TEST_HOOK
/*
 * Function to dump the event channel statistics for all device.
 */
void vio_host_dump_evt_chn(void)
{
    sgxlkl_host_info("[ SGXLKL VIRTIO EVT CHANNEL DEBUG INFO ]\n");
    for (int dev_id = 0; dev_id < _evt_chn_num; dev_id++)
    {
        host_dev_config_t* cfg = &_dev_cfg[dev_id];
        host_evt_channel_t* hevt = cfg->host_evt_chn;
        evt_t eevt_c = *hevt->enclave_evt_channel;
        evt_t hevt_c = hevt->host_evt_channel;

        sgxlkl_host_info(
            "[ dev_id = %d eevt_chn = %d hevt_chn = %d ]\n",
            dev_id,
            eevt_c,
            hevt_c);
    }
}
#endif
