#ifndef _VIO_EVENT_CHANNEL_H
#define _VIO_EVENT_CHANNEL_H

#include "openenclave/bits/types.h"

#define NSEC_PER_SECOND 1000000000UL

typedef uint64_t evt_t;

typedef struct enc_evt_channel
{
    evt_t enclave_evt_channel;
    evt_t* host_evt_channel;
    uint32_t* qidx_p;
} enc_evt_channel_t;

typedef struct enc_dev_config
{
    uint8_t dev_id;
    enc_evt_channel_t* enc_evt_chn;
    evt_t evt_processed;
} enc_dev_config_t;

#endif //_VIO_EVENT_CHANNEL_H
