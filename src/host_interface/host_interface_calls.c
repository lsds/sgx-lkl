#include <cpuid.h>
#include <errno.h>
#include <host/sgxlkl_util.h>
#include <host/vio_host_event_channel.h>
#include <host/virtio_debug.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

/* Function to register the enclaves signal handler */
extern void register_enclave_signal_handler(void* signal_handler);

/*
 * Function to stop the host network device
 */
extern int net_dev_remove(uint8_t dev_id);

/* Used for signaling the sleeping ethread in case of any virtio event */
static pthread_cond_t cond;
static pthread_mutex_t mtx;

/*
 * Function to initialize all the setting of the host interface
 */
void sgxlkl_host_interface_initialization(void)
{
    pthread_condattr_t cattr;
    pthread_condattr_init(&cattr);

    pthread_mutex_init(&mtx, NULL);
    pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
    pthread_cond_init(&cond, &cattr);
}

void sgxlkl_host_idle_ethread(size_t sleeptime_ns)
{
    struct timespec timeout, now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    timeout.tv_sec = now.tv_sec;
    timeout.tv_nsec = now.tv_nsec + sleeptime_ns;
    if (timeout.tv_nsec >= NSEC_PER_SECOND)
    {
        timeout.tv_sec += timeout.tv_nsec / NSEC_PER_SECOND;
        timeout.tv_nsec = timeout.tv_nsec % NSEC_PER_SECOND;
    }

#if DEBUG && VIRTIO_TEST_HOOK
    /* make ethread to sleep for ETHREAD_SLEEP_TIMEOUT_SECS seconds to
     * make all the lthread (LKL & enclave app) to quiesce. The sleeping
     * ethreads will be wake up by device event or at timeout of 120 seconds */
    if (virtio_debug_get_evt_chn_state())
    {
        timeout.tv_sec = now.tv_sec + virtio_debug_get_sleep_timeout();
        timeout.tv_nsec = now.tv_nsec;
        sgxlkl_host_info(
            "ethread entering sleep for %d secs\n",
            virtio_debug_get_sleep_timeout());
    }
#endif
    pthread_mutex_lock(&mtx);

    int rc = pthread_cond_timedwait(&cond, &mtx, &timeout);
    if (rc != 0 && rc != ETIMEDOUT)
        sgxlkl_host_info("%s: failed: %d \n", __func__, rc);

    pthread_mutex_unlock(&mtx);

    return;
}

void sgxlkl_signal_vio_event(void)
{
    pthread_mutex_lock(&mtx);

    int rc = pthread_cond_broadcast(&cond);
    if (rc != 0)
        sgxlkl_host_info("%s: failed: %d\n", __func__, rc);

    pthread_mutex_unlock(&mtx);

    return;
}

void sgxlkl_host_sw_register_signal_handler(void* signal_handler)
{
    register_enclave_signal_handler(signal_handler);
}

int sgxlkl_host_syscall_mprotect(void* addr, size_t len, int prot)
{
    return mprotect(addr, len, prot);
}

void sgxlkl_host_hw_cpuid(
    uint32_t leaf,
    uint32_t subleaf,
    uint32_t* eax,
    uint32_t* ebx,
    uint32_t* ecx,
    uint32_t* edx)
{
    if (eax)
        *eax = 0;

    if (ebx)
        *ebx = 0;

    if (ecx)
        *ecx = 0;

    if (edx)
        *edx = 0;

    __cpuid_count(leaf, subleaf, *eax, *ebx, *ecx, *edx);
}

void sgxlkl_host_hw_rdtsc(uint32_t* eax, uint32_t* edx)
{
    uint32_t hi, lo;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    *eax = lo;
    *edx = hi;
}

void sgxlkl_host_device_request(int dev_id)
{
    sgxlkl_host_handle_device_request(dev_id);
}

void sgxlkl_host_netdev_remove(uint8_t dev_id)
{
    net_dev_remove(dev_id);
}

/*
 * Shutdown notification invoked by guest to notify host
 */
void sgxlkl_host_shutdown_notification(void)
{
    /* Notify host device for the shutdown evt */
    vio_host_notify_guest_shutdown_evt();
}
