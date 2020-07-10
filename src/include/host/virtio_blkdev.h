#ifndef BLK_DEVICE_INT_H
#define BLK_DEVICE_INT_H

#include <host/virtio_dev.h>
#include <inttypes.h>
#include <shared/virtio_ring_buff.h>

#define PAGE_SIZE 4096

/* The following are copied from skbuff.h */
#if (65536 / PAGE_SIZE + 1) < 16
#define MAX_SKB_FRAGS 16UL
#else
#define MAX_SKB_FRAGS (65536 / PAGE_SIZE + 1)
#endif

#define VIRTIO_REQ_MAX_BUFS (MAX_SKB_FRAGS + 2)

struct virtio_blk_outhdr
{
#define LKL_DEV_BLK_TYPE_READ 0
#define LKL_DEV_BLK_TYPE_WRITE 1
#define LKL_DEV_BLK_TYPE_FLUSH 4
#define LKL_DEV_BLK_TYPE_FLUSH_OUT 5
    /* VIRTIO_BLK_T* */
    uint32_t type;
    /* io priority. */
    uint32_t ioprio;
    /* Sector (ie. 512 byte offset) */
    uint64_t sector;
};

struct virtio_blk_req_trailer
{
    uint8_t status;
};

struct virtio_blk_config
{
    /* The capacity (in 512-byte sectors). */
    uint64_t capacity;
    /* The maximum segment size (if LKL_VIRTIO_BLK_F_SIZE_MAX) */
    uint32_t size_max;
    /* The maximum number of segments (if LKL_VIRTIO_BLK_F_SEG_MAX) */
    uint32_t seg_max;
    /* geometry of the device (if LKL_VIRTIO_BLK_F_GEOMETRY) */
    struct host_virtio_blk_geometry
    {
        uint16_t cylinders;
        uint8_t heads;
        uint8_t sectors;
    } geometry;

    /* block size of device (if LKL_VIRTIO_BLK_F_BLK_SIZE) */
    uint32_t blk_size;

    /* the next 4 entries are guarded by LKL_VIRTIO_BLK_F_TOPOLOGY  */
    /* exponent for physical block per logical block. */
    uint8_t physical_block_exp;
    /* alignment offset in logical blocks. */
    uint8_t alignment_offset;
    /* minimum I/O size without performance penalty in logical blocks. */
    uint16_t min_io_size;
    /* optimal sustained I/O size in logical blocks. */
    uint32_t opt_io_size;

    /* writeback mode (if LKL_VIRTIO_BLK_F_CONFIG_WCE) */
    uint8_t wce;
    uint8_t unused;

    /* number of vqs, only available when LKL_VIRTIO_BLK_F_MQ is set */
    uint16_t num_queues;
} __attribute__((packed));

#define LKL_DEV_BLK_STATUS_OK 0
#define LKL_DEV_BLK_STATUS_IOERR 1
#define LKL_DEV_BLK_STATUS_UNSUP 2
struct virtio_blk_dev
{
    struct virtio_dev dev;
    struct virtio_blk_config config;
};
#endif
