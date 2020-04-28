#ifndef _VIO_EVENT_CHANNEL_H
#define _VIO_EVENT_CHANNEL_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#define NSEC_PER_SECOND 1000000000UL

typedef uint64_t evt_t;

typedef struct host_evt_channel
{
    evt_t host_evt_channel;
    evt_t* enclave_evt_channel;
    uint32_t qidx_p;
} host_evt_channel_t;

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

typedef struct host_dev_task_config
{
    uint8_t dev_id;
    host_evt_channel_t* host_evt_chn;
    evt_t evt_processed;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} host_dev_config_t;

#endif //_VIO_EVENT_CHANNEL_H
