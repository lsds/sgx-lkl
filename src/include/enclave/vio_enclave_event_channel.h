#ifndef _VIO_ENCLAVE_EVENT_CHANNEL_H
#define _VIO_ENCLAVE_EVENT_CHANNEL_H

#include <shared/vio_event_channel.h>

/*
 * Function to notify the enclave event handler for the virtio write request.
 * This function invokes ocall to notify the host for the guest request
 *
 * @dev_id: Device identifier for which the request is intended.
 * @qidx: queue id of the request.
 */
void vio_enclave_notify_enclave_event(uint8_t dev_id, uint32_t qidx);

#endif //_VIO_ENCLAVE_EVENT_CHANNEL_H
