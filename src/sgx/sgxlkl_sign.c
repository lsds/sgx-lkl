/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sgxlkl_sign_cmdline.h"
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

    enclave_sign(libpath, key, heapsize, stacksize, threads);
    cmdline_parser_free(&args_info);
    return 0;
}
