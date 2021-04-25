#ifndef VIRTIO_RING_BUFF_H
#define VIRTIO_RING_BUFF_H

#include "shared/oe_compat.h"

/* This marks a buffer as continuing via the next field. */
#define LKL_VRING_DESC_F_NEXT 1
/* This marks a buffer as write-only (otherwise read-only). */
#define LKL_VRING_DESC_F_WRITE 2
/* This means the buffer contains a list of buffer descriptors. */
#define LKL_VRING_DESC_F_INDIRECT 4

#define LKL_VRING_PACKED_DESC_F_AVAIL	7
#define LKL_VRING_PACKED_DESC_F_USED	15

#define LKL_VRING_PACKED_EVENT_FLAG_ENABLE 0x0
#define LKL_VRING_PACKED_EVENT_FLAG_DISABLE 0x1
#define LKL_VRING_PACKED_EVENT_FLAG_DESC 0x2


struct virtq_desc
{
    /* Address (guest-physical). */
    uint64_t addr;
    /* Length. */
    uint32_t len;
    /* The flags as indicated above. */
    uint16_t flags;
    /* We chain unused descriptors via this, too */
    uint16_t next;
};

struct virtq_avail
{
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
};

struct virtq_used_elem
{
    /* Index of start of used descriptor chain. */
    uint32_t id;
    /* Total length of the descriptor chain which was used (written to) */
    uint32_t len;
};

struct virtq_used
{
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[];
};

struct virtq
{
    uint32_t num_max;
    _Atomic(uint32_t) num;
    _Atomic(uint32_t) ready;
    uint32_t max_merge_len;

    _Atomic(struct virtq_desc*) desc;
    _Atomic(struct virtq_avail*) avail;
    _Atomic(struct virtq_used*) used;
    uint16_t last_avail_idx;
    uint16_t last_used_idx_signaled;
};

struct virtq_packed_desc
{
    uint64_t addr;
    uint32_t len;
    uint16_t id;
    uint16_t flags;
};

struct virtq_packed_desc_event
{
    uint16_t off_wrap;
    uint16_t flags;
};

struct virtq_packed
{
    uint32_t num_max;
    _Atomic(uint32_t) ready;
    _Atomic(uint32_t) num;
    uint32_t max_merge_len;

    //Add supression flags where necessary
    _Atomic(struct virtq_packed_desc*) desc;
    _Atomic(struct virtq_packed_desc_event*) driver;
    _Atomic(struct virtq_packed_desc_event*) device;
    bool device_wrap_counter; //Initialise to 1, flip when we change last descriptor as used
    bool driver_wrap_counter; //Initialise to 1 and flip when when avail_desc_idx becomes greater than queue and we need to wrap around it
    uint16_t avail_desc_idx; //We increment this for each avail event we process
    uint16_t used_desc_idx;
    bool unprocessed_used_desc;
};
#endif
