#ifndef SGXLKL_PARAMS_H
#define SGXLKL_PARAMS_H

#include <stdint.h>

#define SGXLKL_APP_CONFIG 0
#define SGXLKL_CMDLINE 1
#define SGXLKL_CWD 2
#define SGXLKL_DEBUGMOUNT 3
#define SGXLKL_ESPINS 4
#define SGXLKL_ESLEEP 5
#define SGXLKL_ETHREADS 6
#define SGXLKL_ETHREADS_AFFINITY 7
#define SGXLKL_GW4 8
#define SGXLKL_HD 9
#define SGXLKL_HD_KEY 10
#define SGXLKL_HD_RO 11
#define SGXLKL_HDS 12
#define SGXLKL_HD_VERITY 13
#define SGXLKL_HD_VERITY_OFFSET 14
#define SGXLKL_HOSTNAME 15
#define SGXLKL_HOSTNET 16
#define SGXLKL_IP4 17
#define SGXLKL_KERNEL_VERBOSE 18
#define SGXLKL_MASK4 19
#define SGXLKL_MAX_USER_THREADS 20
#define SGXLKL_MMAP_FILES 21
#define SGXLKL_PRINT_APP_RUNTIME 22
#define SGXLKL_STACK_SIZE 23
#define SGXLKL_SYSCTL 24
#define SGXLKL_TAP 25
#define SGXLKL_TAP_MTU 26
#define SGXLKL_TAP_OFFLOAD 27
#define SGXLKL_TRACE_HOST_SYSCALL 28
#define SGXLKL_TRACE_INTERNAL_SYSCALL 29
#define SGXLKL_TRACE_LKL_SYSCALL 30
#define SGXLKL_TRACE_IGNORED_SYSCALL 31
#define SGXLKL_TRACE_UNSUPPORTED_SYSCALL 32
#define SGXLKL_TRACE_REDIRECT_SYSCALL 33
#define SGXLKL_TRACE_MMAP 34
#define SGXLKL_TRACE_SYSCALL 35
#define SGXLKL_TRACE_THREAD 36
#define SGXLKL_VERBOSE 37
#define SGXLKL_WG_IP 38
#define SGXLKL_WG_PORT 39
#define SGXLKL_WG_KEY 40
#define SGXLKL_WG_PEERS 41
#define SGXLKL_OE_HEAP_PAGE_COUNT 42
#define SGXLKL_ENABLE_SWIOTLB 43
#define SGXLKL_HD_OVERLAY 44
#define SGXLKL_HOST_IMPORT_ENV 45

int sgxlkl_parse_params_from_str(char* str, char** err);

int sgxlkl_parse_params_from_file(const char* path, char** err);

int sgxlkl_configured(int opt);

int sgxlkl_config_bool(int opt_key);

uint64_t sgxlkl_config_uint64(int opt_key);

char* sgxlkl_config_str(int opt_key);

#endif /* SGXLKL_PARAMS_H */
