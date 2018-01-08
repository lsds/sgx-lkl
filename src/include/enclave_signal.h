/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * 
 * This file is part of SGX-LKL.
 * 
 * SGX-LKL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SGX-LKL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SGX-LKL.  If not, see <http://www.gnu.org/licenses/>.
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
