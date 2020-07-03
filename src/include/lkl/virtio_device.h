#ifndef __LKL_VIRTIO_DEVICE_H__
#define __LKL_VIRTIO_DEVICE_H__

struct enclave_disk_config;
struct virtio_dev;

/*
 * Function to setup the block device and register it with virtio drivers
 */
void lkl_add_disks(struct enclave_disk_config* disks, size_t num_disks);

/*
 * Function to register the block device with mmio drivers and acquire irq
 */
extern int lkl_virtio_netdev_add(struct virtio_dev* netdev);

/*
 * Function to register the console device with mmio drivers and acquire irq
 */
extern int lkl_virtio_console_add(struct virtio_dev* console);

#endif //__LKL_VIRTIO_DEVICE_H__
