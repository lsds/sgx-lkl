#ifndef _VIO_HOST_EVENT_CHANNEL_H
#define _VIO_HOST_EVENT_CHANNEL_H

#include <shared/sgxlkl_config.h>
#include <shared/vio_event_channel.h>

#define HOST_NETWORK_DEV_COUNT 1
#define HOST_CONSOLE_DEV_COUNT 1

/*
 * Function to initialize the host device configuration. This function
 * allocates the required memory for host & enclave event channel & setup
 * bounce buffer for virtio
 */
int initialize_host_device_configuration(
    sgxlkl_config_t* cfg,
    host_dev_config_t** host_dev_cfg,
    enc_dev_config_t** enc_dev_config,
    uint8_t evt_chn_number);

/*
 * Function to initialize the event channel at host side (backend).
 *
 * @dev_cfg : device configuration
 * @evt_channel_num : total number of event channels
 */
void vio_host_initialize_device_cfg(
    host_dev_config_t* dev_cfg,
    uint8_t evt_channel_num);

/*
 * Function to wait for an event from guest(enclave)
 *
 * @dev_id : Device identifier waiting for an event
 * @timeout_ms: timeout in milliseconds
 */
void vio_host_process_enclave_event(uint8_t dev_id, int timeout_ms);

/*
 * Function to notify guest when the virtio processing is completed.
 * It will only notify host when the guest task is sleeping.
 *
 * @dev_id : Device identifier for waking up the guest sleeping task
 */
int vio_host_notify_host_event(uint8_t dev_id);

/*
 * Function is to wake up the sleeping host tasks.
 *
 * @dev_id : Device identifier for waking up the required task
 */
void sgxlkl_host_handle_device_request(uint8_t dev_id);

/*
 * Function to dump the event channel statistics.
 */
void vio_host_dump_evt_chn(void);

/*
 * Function to set shutdown evt for host device
 */
void vio_host_notify_guest_shutdown_evt(void);

/*
 * Function to check whether guest notified shutdown evt
 */
int vio_host_check_guest_shutdown_evt(void);

#endif //_VIO_HOST_EVENT_CHANNEL_H
