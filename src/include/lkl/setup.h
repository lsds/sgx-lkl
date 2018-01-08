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

#include "enclave_config.h"

// 16 MiB is plenty enough of RAM for LKL, except if you want to run tmpfs benchmarks
// (in which case don't edit this, use SGXLKL_LKLRAM environment variable instead)
#define DEFAULT_LKL_RAM (1024*1024*16)
#define DEFAULT_LKL_CMDLINE ""

// Hardcoded encryption key. In an SGX-ready production environment, this would be
// generated on the first run, then sealed and unsealed at each boot.
#define DEFAULT_LKL_DISKENCKEY "01020304050607080910111213141516171819202123242526272829303132"

void __lkl_start_init(enclave_config_t* encl);
void __lkl_exit();

