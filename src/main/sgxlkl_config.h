#ifndef SGXLKL_CONFIG_H
#define SGXLKL_CONFIG_H

#define SGXLKL_APP_CONFIG               0
#define SGXLKL_CMDLINE                  1
#define SGXLKL_DEBUGMOUNT               2
#define SGXLKL_ESPINS                   3
#define SGXLKL_ESLEEP                   4
#define SGXLKL_ETHREADS                 5
#define SGXLKL_ETHREADS_AFFINITY        6
#define SGXLKL_GETTIME_VDSO             7
#define SGXLKL_GW4                      8
#define SGXLKL_HD                       9
#define SGXLKL_HD_KEY                   10
#define SGXLKL_HD_RO                    11
#define SGXLKL_HDS                      12
#define SGXLKL_HD_VERITY                13
#define SGXLKL_HD_VERITY_OFFSET         14
#define SGXLKL_HEAP                     15
#define SGXLKL_HOSTNAME                 16
#define SGXLKL_HOSTNET                  17
#define SGXLKL_IAS_CERT                 18
#define SGXLKL_IAS_KEY_FILE             19
#define SGXLKL_IAS_QUOTE_TYPE           20
#define SGXLKL_IAS_SERVER               21
#define SGXLKL_IAS_SPID                 22
#define SGXLKL_IP4                      23
#define SGXLKL_KERNEL_VERBOSE           24
#define SGXLKL_KEY                      25
#define SGXLKL_MASK4                    26
#define SGXLKL_MAX_USER_THREADS         27
#define SGXLKL_MMAP_FILES               28
#define SGXLKL_NON_PIE                  29
#define SGXLKL_PRINT_APP_RUNTIME        30
#define SGXLKL_PRINT_HOST_SYSCALL_STATS 31
#define SGXLKL_REAL_TIME_PRIO           32
#define SGXLKL_REMOTE_ATTEST_PORT       33
#define SGXLKL_REMOTE_CMD_PORT          34
#define SGXLKL_REMOTE_CMD_ETH0          35
#define SGXLKL_REMOTE_CONFIG            36
#define SGXLKL_REPORT_NONCE             37
#define SGXLKL_SHMEM_FILE               38
#define SGXLKL_SHMEM_SIZE               39
#define SGXLKL_SIGPIPE                  40
#define SGXLKL_SSLEEP                   41
#define SGXLKL_SSPINS                   42
#define SGXLKL_STACK_SIZE               43
#define SGXLKL_STHREADS                 44
#define SGXLKL_STHREADS_AFFINITY        45
#define SGXLKL_TAP                      46
#define SGXLKL_TAP_MTU                  47
#define SGXLKL_TAP_OFFLOAD              48
#define SGXLKL_TRACE_HOST_SYSCALL       49
#define SGXLKL_TRACE_INTERNAL_SYSCALL   50
#define SGXLKL_TRACE_LKL_SYSCALL        51
#define SGXLKL_TRACE_MMAP               52
#define SGXLKL_TRACE_SYSCALL            53
#define SGXLKL_TRACE_THREAD             54
#define SGXLKL_VERBOSE                  55
#define SGXLKL_WG_IP                    56
#define SGXLKL_WG_PORT                  57
#define SGXLKL_WG_KEY                   58
#define SGXLKL_WG_PEERS                 59


#define DEFAULT_SGXLKL_GW4 "10.0.1.254"
/* The default heap size will only be used if no heap size is specified and
 * either we are in simulation mode, or we are in HW mode and a key is provided
 * via SGXLKL_KEY.
 */
#define DEFAULT_SGXLKL_HEAP_SIZE 200 * 1024 * 1024
#define DEFAULT_SGXLKL_HOSTNAME "lkl"
#define DEFAULT_SGXLKL_IAS_QUOTE_TYPE "Unlinkable"
#define DEFAULT_SGXLKL_IAS_SERVER "test-as.sgx.trustedservices.intel.com:443"
#define DEFAULT_SGXLKL_IP4 "10.0.1.1"
#define DEFAULT_SGXLKL_MASK4 24
#define DEFAULT_SGXLKL_MAX_USER_THREADS 256
#define DEFAULT_SGXLKL_ESLEEP 16000
#define DEFAULT_SGXLKL_ETHREADS 1
#define DEFAULT_SGXLKL_STHREADS 4
#define DEFAULT_SGXLKL_ESPINS 500
#define DEFAULT_SGXLKL_SSLEEP 4000
#define DEFAULT_SGXLKL_SSPINS 100
#define DEFAULT_SGXLKL_STACK_SIZE 512 * 1024
#define DEFAULT_SGXLKL_TAP "sgxlkl_tap0"
#define DEFAULT_SGXLKL_WG_IP "11.0.0.1"
#define DEFAULT_SGXLKL_WG_PORT 56002
#define DEFAULT_SGXLKL_REMOTE_ATTEST_PORT 56000
#define DEFAULT_SGXLKL_REMOTE_CMD_PORT 56001

#define MAX_SGXLKL_ETHREADS 1024
#define MAX_SGXLKL_MAX_USER_THREADS 65536
#define MAX_SGXLKL_STHREADS 1024

int parse_sgxlkl_config(char *path, char **err);
int parse_sgxlkl_config_from_str(char *str, char **err);
int sgxlkl_configured(int opt);
int sgxlkl_config_bool(int opt_key);
uint64_t sgxlkl_config_uint64(int opt_key);
char *sgxlkl_config_str(int opt_key);

#endif /* SGXLKL_CONFIG_H */
