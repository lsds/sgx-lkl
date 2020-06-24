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
#define SGXLKL_GW4 10
#define SGXLKL_HD 11
#define SGXLKL_HD_KEY 12
#define SGXLKL_HD_RO 13
#define SGXLKL_HDS 14
#define SGXLKL_HD_VERITY 15
#define SGXLKL_HD_VERITY_OFFSET 16
#define SGXLKL_HEAP 17
#define SGXLKL_HOSTNAME 18
#define SGXLKL_HOSTNET 19
#define SGXLKL_IP4 20
#define SGXLKL_KERNEL_VERBOSE 21
#define SGXLKL_MASK4 23
#define SGXLKL_MAX_USER_THREADS 24
#define SGXLKL_MMAP_FILES 25
#define SGXLKL_PRINT_APP_RUNTIME 27
#define SGXLKL_PRINT_HOST_SYSCALL_STATS 28
#define SGXLKL_REPORT_NONCE 31
#define SGXLKL_SHMEM_FILE 32
#define SGXLKL_SHMEM_SIZE 33
#define SGXLKL_STACK_SIZE 37
#define SGXLKL_SYSCTL 40
#define SGXLKL_TAP 41
#define SGXLKL_TAP_MTU 42
#define SGXLKL_TAP_OFFLOAD 43
#define SGXLKL_TRACE_HOST_SYSCALL 44
#define SGXLKL_TRACE_INTERNAL_SYSCALL 45
#define SGXLKL_TRACE_LKL_SYSCALL 46
#define SGXLKL_TRACE_IGNORED_SYSCALL 47
#define SGXLKL_TRACE_UNSUPPORTED_SYSCALL 48
#define SGXLKL_TRACE_REDIRECT_SYSCALL 49
#define SGXLKL_TRACE_MMAP 50
#define SGXLKL_TRACE_SYSCALL 51
#define SGXLKL_TRACE_THREAD 52
#define SGXLKL_VERBOSE 53
#define SGXLKL_WG_IP 56
#define SGXLKL_WG_PORT 57
#define SGXLKL_WG_KEY 58
#define SGXLKL_WG_PEERS 59
#define SGXLKL_OE_HEAP_PAGE_COUNT 60
#define SGXLKL_ENABLE_SWIOTLB 65
#define SGXLKL_HD_OVERLAY 66
#define SGXLKL_HOST_IMPORT_ENV 67

int sgxlkl_parse_params_from_str(char* str, char** err);

int sgxlkl_parse_params_from_file(const char* path, char** err);

int sgxlkl_configured(int opt);

int sgxlkl_config_bool(int opt_key);

uint64_t sgxlkl_config_uint64(int opt_key);

char* sgxlkl_config_str(int opt_key);

#endif /* SGXLKL_PARAMS_H */
