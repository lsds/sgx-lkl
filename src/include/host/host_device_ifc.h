#ifndef HOST_DEVICE_IFC_H
#define HOST_DEVICE_IFC_H

#include "shared/sgxlkl_config.h"
#include "shared/virtio_ring_buff.h"

/* Block device interface */

/*
 * Function to initialize the block device configuration and setup the virtio
 * device and queue which is shared with guest for virtio processing
 */
int blk_device_init(struct enclave_disk_config* disk, int enable_swiotlb);

/*
 * Block device backend task which listens for the guest request using event
 * channel and process the request and notify the guest using ecall
 */
void* blkdevice_thread(void* args);

/* Network device interface */
/*
 * Function to initialize the network device configuration and setup the virtio
 * network device and queues which is shared with gust for virtio processing.
 * This function starts a polling task which keep monitoring the IO over tap
 * interface and initiate a virtio processing and notifies guest.
 */
int netdev_init(sgxlkl_config_t* config);

/*
 * Network device backend task which listens for the guest request using event
 * channel and process the request and notify the guest using ecall
 */
void* netdev_task(void* arg);

/* Console device interface */

/* Function to initialize the console device configuration and setup the virtio
 * device and queue which is shared with guest for virtio processing
 */
int virtio_console_init(sgxlkl_config_t* cfg, host_dev_config_t* host_cfg);

/*
 * Console device backend task which listens for the guest request using event
 * channel and process the request and notify the guest using ecall
 */
void* console_task(void* arg);

#endif // HOST_DEVICE_IFC_H
