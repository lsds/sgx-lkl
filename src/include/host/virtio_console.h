#ifndef LKL_VIRTIO_CONSOLE_H
#define LKL_VIRTIO_CONSOLE_H

#include <host/virtio_dev.h>
#include <host/virtio_types.h>
#include <inttypes.h>
#include <shared/virtio_ring_buff.h>

/* Feature flags for virtio console to communicate the host
 * capabilities to guest */
#define VIRTIO_CONSOLE_F_SIZE 0

#endif
