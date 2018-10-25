/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#ifndef ENCLAVE_SIGNAL_H
#define ENCLAVE_SIGNAL_H

#include "enclave_config.h"

/* Enclave signal info */
typedef struct {
    int signum;
    void *arg;
} enclave_signal_info_t;

void __enclave_signal_handler(gprsgx_t *regs, enclave_signal_info_t *siginfo);

#endif /* ENCLAVE_SIGNAL_H */
