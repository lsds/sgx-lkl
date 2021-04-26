#ifndef VIRTIO_RING_BUFF_H
#define VIRTIO_RING_BUFF_H

#include "shared/oe_compat.h"

/* This marks a buffer as continuing via the next field. */
#define LKL_VRING_DESC_F_NEXT 1
/* This marks a buffer as write-only (otherwise read-only). */
#define LKL_VRING_DESC_F_WRITE 2
/* This means the buffer contains a list of buffer descriptors. */
#define LKL_VRING_DESC_F_INDIRECT 4
/*
 * Mark a descriptor as available or used in packed ring.
 * Notice: they are defined as shifts instead of shifted values.
 */
#define LKL_VRING_PACKED_DESC_F_AVAIL	7
#define LKL_VRING_PACKED_DESC_F_USED	15
/* Enable events in packed ring. */
#define LKL_VRING_PACKED_EVENT_FLAG_ENABLE 0x0
/* Disable events in packed ring. */
#define LKL_VRING_PACKED_EVENT_FLAG_DISABLE 0x1
/*
 * Enable events for a specific descriptor in packed ring.
 * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
 * Only valid if VIRTIO_RING_F_EVENT_IDX has been negotiated.
 */
#define LKL_VRING_PACKED_EVENT_FLAG_DESC 0x2
/*
 * Wrap counter bit shift in event suppression structure
 * of packed ring.
 */
#define LKL_VRING_PACKED_EVENT_F_WRAP_CTR 15


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
    /* Address (guest-physical). */
    uint64_t addr;
    /* Length. */
    uint32_t len;
    /* Buffer ID. */
    uint16_t id;
    /* The flags as indicated above. */
    uint16_t flags;
};

struct virtq_packed_desc_event
{
    /* Descriptor Ring Change Event Offset/Wrap Counter. */
    uint16_t off_wrap;
    /* Descriptor Ring Change Event Flags. */
    uint16_t flags;
};

struct virtq_packed
{
    uint32_t num_max;
    _Atomic(uint32_t) ready;
    _Atomic(uint32_t) num;
    uint32_t max_merge_len;

    _Atomic(struct virtq_packed_desc*) desc;
    _Atomic(struct virtq_packed_desc_event*) driver;
    _Atomic(struct virtq_packed_desc_event*) device;
    bool device_wrap_counter;
    bool driver_wrap_counter;
    uint16_t avail_desc_idx;
    uint16_t used_desc_idx;
};
#endif
