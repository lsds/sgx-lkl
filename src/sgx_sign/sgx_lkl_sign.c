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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sgx_lkl_sign_cmdline.h"
#include "libsgx.h"

#define DIV_ROUNDUP(x, y)   (((x)+((y)-1))/(y))

int main(int argc, char** argv) {
    struct gengetopt_args_info args_info;
    if (cmdline_parser (argc, argv, &args_info) != 0)
        exit(1);

    long heapsize = args_info.heapsize_arg;
    long stacksize = DIV_ROUNDUP(args_info.stacksize_arg, sysconf(_SC_PAGESIZE));
    long threads = args_info.threads_arg;
    char* key = args_info.key_arg;
    char* libpath = args_info.file_arg;

    enclave_sign(libpath, key, heapsize, stacksize, threads, 1);
    cmdline_parser_free(&args_info);
    return 0;
}
