#ifndef _LKL_LIB_VIRTIO_H
#define _LKL_LIB_VIRTIO_H

#include <lkl_host.h>
#include <stdint.h>

#define container_of(ptr, type, member) \
    (type*)((char*)(ptr) - __builtin_offsetof(type, member))

struct virtio_dev
{
    uint32_t device_id;
    uint32_t vendor_id;
    uint64_t device_features;
    _Atomic(uint32_t) device_features_sel;
    uint64_t driver_features;
    _Atomic(uint32_t) driver_features_sel;
    _Atomic(uint32_t) queue_sel;
    union {
        struct {
            struct virtq* queue;
        }split;

        struct {
            struct virtq_packed* queue;
        }packed;
    };
    uint32_t queue_notify;
    _Atomic(uint32_t) int_status;
    _Atomic(uint32_t) status;
    uint32_t config_gen;

    struct virtio_dev_ops* ops;
    int irq;
    void* config_data;
    int config_len;
    void* base;
    uint32_t virtio_mmio_id;
};

/*
 * Function to setup the virtio device and acquire the irq.
 */
int lkl_virtio_dev_setup(
    struct virtio_dev* dev,
    struct virtio_dev* dev_host,
    int mmio_size,
    void* virtio_req_complete);

/*
 * Function to generate the irq for notifying the frontend driver
 * about the request completion by host/backend driver.
 */
void lkl_virtio_deliver_irq(uint8_t dev_id);

/*
 * Function to allocate memory for a shadow virtio dev
 */
struct virtio_dev* alloc_shadow_virtio_dev();

#endif //_LKL_LIB_VIRTIO_H