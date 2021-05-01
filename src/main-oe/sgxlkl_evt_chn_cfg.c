#include <errno.h>
#include <host/sgxlkl_util.h>
#include <host/vio_host_event_channel.h>
#include <shared/vio_event_channel.h>
#include <stdlib.h>
#include <sys/mman.h>

#define SWIOTLB_BUFFER_SIZE (64UL << 20)
#define SWIOTLB_SIZE SWIOTLB_BUFFER_SIZE + (8UL << 20)

/*
 * Function to configure software io tlb (bounce buffer) for virtio.
 * Host block device driver will not will not be able to access the
 * enclave memory directly and hence bounce buffer needs to be setup
 * to exchange the data between host and enclave.
 */
static inline void* configure_software_io_tlb(uint32_t size)
{
    void* bounce_buffer = NULL;

    /* Allocate memory for bounce buffer for virtio */
    bounce_buffer = mmap(
        0, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (bounce_buffer == MAP_FAILED)
        sgxlkl_host_fail("mem allocation for setting up bounce buffer\n");

    return bounce_buffer;
}

/*
 * Function to allocate memory for host & guest event channel and initialize
 * it with default values.
 * @h_evt_channel : host event channel
 * @e_evt_channel : guest event channel
 * evt_channel_num: number of event channels
 */
static void host_dev_event_channel_init(
    host_evt_channel_t** h_evt_channel,
    enc_evt_channel_t** e_evt_channel,
    int evt_channel_num)
{
    /* Allocate memory for host event channel */
    host_evt_channel_t* host_evt_channel = (host_evt_channel_t*)calloc(
        sizeof(host_evt_channel_t), evt_channel_num);
    if (!host_evt_channel)
        sgxlkl_host_fail("host evt channel allocation failed: %d \n", errno);

    enc_evt_channel_t* enc_evt_channel =
        (enc_evt_channel_t*)calloc(sizeof(enc_evt_channel_t), evt_channel_num);
    if (!enc_evt_channel)
        sgxlkl_host_fail("guest evt channel allocation failed: %d \n", errno);

    for (int index = 0; index < evt_channel_num; index++)
    {
        host_evt_channel[index].host_evt_channel = 0;
        host_evt_channel[index].enclave_evt_channel =
            &enc_evt_channel[index].enclave_evt_channel;
        host_evt_channel[index].qidx_p = 0;

        enc_evt_channel[index].enclave_evt_channel = 0;
        enc_evt_channel[index].host_evt_channel =
            &host_evt_channel[index].host_evt_channel;
        enc_evt_channel[index].qidx_p = &host_evt_channel[index].qidx_p;
    }
    *h_evt_channel = host_evt_channel;
    *e_evt_channel = enc_evt_channel;

    return;
}

/*
 * Function to allocate memory for host & guest device configurations.
 * @h_dev_config : host device configuration
 * @e_dev_config : guest device configuration
 * @evt_channel_num : number of event channel
 */
static void host_dev_cfg_init(
    host_dev_config_t** h_dev_config,
    enc_dev_config_t** e_dev_config,
    int evt_channel_num)
{
    host_evt_channel_t* host_evt_channel = NULL;
    enc_evt_channel_t* enc_evt_channel = NULL;

    /* Allocate host device configuration memory */
    host_dev_config_t* host_dev_cfg =
        (host_dev_config_t*)calloc(sizeof(host_dev_config_t), evt_channel_num);

    if (!host_dev_cfg)
        sgxlkl_host_fail("Failed to allocate memory (host): %d\n", errno);

    enc_dev_config_t* enc_dev_cfg =
        (enc_dev_config_t*)calloc(sizeof(enc_dev_config_t), evt_channel_num);

    if (!enc_dev_cfg)
        sgxlkl_host_fail("Failed to allocate memory (enclave): %d \n", errno);

    host_dev_event_channel_init(
        &host_evt_channel, &enc_evt_channel, evt_channel_num);

    for (int index = 0; index < evt_channel_num; index++)
    {
        host_dev_config_t* hdev_cfg = &host_dev_cfg[index];

        hdev_cfg->dev_id = (uint8_t)index;
        hdev_cfg->host_evt_chn = &host_evt_channel[index];
        hdev_cfg->evt_processed = 0;

        /* Initialize the mutex & conditional variable */
        pthread_condattr_t cattr;
        pthread_condattr_init(&cattr);

        pthread_mutex_init(&(hdev_cfg->lock), NULL);
        pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
        pthread_cond_init(&(hdev_cfg->cond), &cattr);

        /* Initiailize the guest configuration */
        enc_dev_config_t* edev_cfg = &enc_dev_cfg[index];
        edev_cfg->dev_id = (uint8_t)index;
        edev_cfg->enc_evt_chn = &enc_evt_channel[index];
    }
    *h_dev_config = host_dev_cfg;
    *e_dev_config = enc_dev_cfg;

    return;
}

/*
 * Function to initialize the device configuration and event channels.
 */
int initialize_host_device_configuration(
    bool swiotlb,
    sgxlkl_shared_memory_t* shm,
    host_dev_config_t** host_dev_cfg,
    enc_dev_config_t** enc_dev_config,
    uint8_t evt_chn_number)
{
    if (swiotlb)
    {
        shm->virtio_swiotlb = configure_software_io_tlb(SWIOTLB_SIZE);
        shm->virtio_swiotlb_size = SWIOTLB_SIZE;
    }

    host_dev_cfg_init(host_dev_cfg, enc_dev_config, evt_chn_number);
    return 0;
}
