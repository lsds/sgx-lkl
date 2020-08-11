#ifndef VIRTIO_RING_BUFF_H
#define VIRTIO_RING_BUFF_H

#include "shared/oe_compat.h"

/* This marks a buffer as continuing via the next field. */
#define LKL_VRING_DESC_F_NEXT 1
/* This marks a buffer as write-only (otherwise read-only). */
#define LKL_VRING_DESC_F_WRITE 2
/* This means the buffer contains a list of buffer descriptors. */
#define LKL_VRING_DESC_F_INDIRECT 4

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

#endif
