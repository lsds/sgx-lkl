#ifndef VIO_HOST_DEBUG_H
#define VIO_HOST_DEBUG_H

#if DEBUG && VIRTIO_TEST_HOOK

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <limits.h>
#include <signal.h>
#include <unistd.h>

#include <sys/types.h>

/* Virtio debug options */
struct virtio_debug
{
    bool virtio_pause_evt_chn;
    bool virtio_blk_debug;
    bool virtio_net_tx_debug;
    bool virtio_net_rx_debug;
    uint64_t virtio_req_count;
};

/* Function to display the different virtio debug options */
void virtio_debug_help(void);

/* Initialize the debug settings */
void virtio_debug_init(void);

/* Function to set the count of request */
void virtio_debug_set_ring_count(uint64_t val);

/* Returns the count of request for block device*/
uint64_t virtio_debug_blk_get_ring_count(void);

/* Gets the request count for tx channel of network device */
uint64_t virtio_debug_net_tx_get_ring_count(void);

/* Gets the request count for tx channel of network device */
uint64_t virtio_debug_net_rx_get_ring_count(void);

/* Gets the current event channel state */
void virtio_debug_set_evt_chn_state(bool val);

/* Sets the event channel state */
bool virtio_debug_get_evt_chn_state(void);

/* Gets the sleep timeout */
uint64_t virtio_debug_get_sleep_timeout(void);

#endif // DEBUG && VIRTIO_TEST_HOOK

#endif // VIO_HOST_DEBUG_H
