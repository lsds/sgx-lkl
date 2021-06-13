#if DEBUG && VIRTIO_TEST_HOOK

#include <host/virtio_debug.h>
#include <string.h>

/* Virtio debug module enables different debug options for virtio device
 * communication. Mechanism to force the guest to sleep and wake up using
 * Linux signals. This will facilitate the test of waking up guest and
 * resume all device access and guest should continue from where it stopped
 * without stall.
 */

/* Control the event channel notification between host & guest */

#define SGXLKL_VIRTIO_PAUSE_TIME 120

/* local variable to hold the virtio debug settings */
static struct virtio_debug vhd;

/* Function to display the different virtio debug options */
void virtio_debug_help(void)
{
    printf("## VirtIO Debugging options ##\n");
    printf(
        "%-35s %s",
        "  SGXLKL_DEBUG_VIO_REQUEST_CNT",
        "Pause after N no of request.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_DEBUG_VIO_BLKDEV",
        "Enable debug for block device.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_DEBUG_VIO_NETDEV_TX",
        "Enable debug for network tx chn.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_DEBUG_VIO_NETDEV_RX",
        "Enable debug for network rx chn.\n");
    printf("\n");
}

/* Initialize the debug settings */
void virtio_debug_init(void)
{
    memset(&vhd, 0, sizeof(struct virtio_debug));
    vhd.virtio_req_count =
        getenv_uint64("SGXLKL_DEBUG_VIO_REQUEST_CNT", 0, ULONG_MAX);
    vhd.virtio_blk_debug = getenv_bool("SGXLKL_DEBUG_VIO_BLKDEV", 0);
    vhd.virtio_net_tx_debug = getenv_bool("SGXLKL_DEBUG_VIO_NETDEV_TX", 0);
    vhd.virtio_net_rx_debug = getenv_bool("SGXLKL_DEBUG_VIO_NETDEV_RX", 0);
}

/*
 * Set the count of request after which the event channel will be paused
 * and guest will be forced to sleep due to inactivity.
 */
void virtio_debug_set_ring_count(uint64_t val)
{
    vhd.virtio_req_count = val;
}

/* Returns the count of request */
uint64_t virtio_debug_blk_get_ring_count(void)
{
    if (vhd.virtio_blk_debug)
        return vhd.virtio_req_count;
    return 0;
}

/* Gets the request count for tx channel of network device */
uint64_t virtio_debug_net_tx_get_ring_count(void)
{
    if (vhd.virtio_net_tx_debug)
        return vhd.virtio_req_count;
    return 0;
}

/* Gets the request count for tx channel of network device */
uint64_t virtio_debug_net_rx_get_ring_count(void)
{
    if (vhd.virtio_net_rx_debug)
        return vhd.virtio_req_count;
    return 0;
}

/* Gets the current event channel state */
bool virtio_debug_get_evt_chn_state(void)
{
    return vhd.virtio_pause_evt_chn;
}

/* Sets the event channel state */
void virtio_debug_set_evt_chn_state(bool val)
{
    vhd.virtio_pause_evt_chn = val;
}

/* Gets the sleep timeout to make ethread sleep */
uint64_t virtio_debug_get_sleep_timeout(void)
{
    return SGXLKL_VIRTIO_PAUSE_TIME;
}

#endif // DEBUG && VIRTIO_TEST_HOOK
