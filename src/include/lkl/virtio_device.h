#ifndef __LKL_VIRTIO_DEVICE_H__
#define __LKL_VIRTIO_DEVICE_H__

struct virtio_dev;
struct sgxlkl_enclave_root_config;
struct sgxlkl_enclave_mount_config;

/*
 * Function to setup the block device and register it with virtio drivers
 */
int lkl_add_disks(
    const struct sgxlkl_enclave_root_config* root,
    const struct sgxlkl_enclave_mount_config* disks,
    size_t num_disks);

/*
 * Function to register the block device with mmio drivers and acquire irq
 */
extern int lkl_virtio_netdev_add(struct virtio_dev* netdev);

/*
 * Function to register the console device with mmio drivers and acquire irq
 */
extern int lkl_virtio_console_add(struct virtio_dev* console);

#endif //__LKL_VIRTIO_DEVICE_H__
