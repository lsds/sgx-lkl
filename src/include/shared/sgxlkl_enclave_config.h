#ifndef SGXLKL_ENCLAVE_CONFIG_H
#define SGXLKL_ENCLAVE_CONFIG_H

#include <elf.h>
#include <shared/shared_memory.h>
#include <shared/vio_event_channel.h>
#include "host/timer_dev.h"
#include "mpmc_queue.h"
#include "time.h"

#define UNKNOWN_MODE 0
#define SW_DEBUG_MODE 1
#define HW_DEBUG_MODE 2
#define HW_RELEASE_MODE 3

/* Maximum path length of mount points for secondary disks */
#define SGXLKL_DISK_MNT_MAX_PATH_LEN 255
#define SGXLKL_REPORT_NONCE_SIZE 32

typedef enum
{
    ENCLAVE_MMAP_FILES_NONE = 0,
    ENCLAVE_MMAP_FILES_PRIVATE = 1,
    ENCLAVE_MMAP_FILES_SHARED = 2
} enclave_mmap_files_t;

typedef enum exit_status_mode
{
    EXIT_STATUS_FULL = 0, /* return true_exit_status */
    EXIT_STATUS_BINARY,   /* return true_exit_status ==  0 ? 0 : 1 */
    EXIT_STATUS_NONE      /* return 0 */
} exit_status_mode_t;

typedef struct sgxlkl_enclave_disk_config
{
    char mnt[SGXLKL_DISK_MNT_MAX_PATH_LEN + 1];
    uint8_t* key; /* binary */
    char* key_id;
    size_t key_len;
    bool fresh_key;
    char* roothash;
    size_t roothash_offset;
    bool readonly;
    bool create;
    size_t size;
    bool overlay;
} sgxlkl_enclave_disk_config_t;

typedef struct sgxlkl_enclave_wg_peer_config
{
    char* key;
    char* allowed_ips;
    char* endpoint;
} sgxlkl_enclave_wg_peer_config_t;

typedef struct sgxlkl_enclave_wg_config
{
    char* ip;
    uint16_t listen_port;
    char* key;
    size_t num_peers;
    sgxlkl_enclave_wg_peer_config_t* peers;
} sgxlkl_enclave_wg_config_t;

typedef struct sgxlkl_app_size_config
{
    uint64_t num_heap_pages;
    uint64_t num_stack_pages;
    uint64_t num_tcs;
} sgxlkl_app_size_config_t;

typedef struct sgxlkl_app_config
{
    char* run;            /* Command to run (argv[0]) */
    char* cwd;            /* Working directory */
    int argc;             /* Length of argv */
    char** argv;          /* Array of application arguments of length argc */
    int envc;             /* Length of envp */
    char** envp;          /* Array of environment variables of length envc */
    int auxc;             /* Length of auxv */
    Elf64_auxv_t** auxv;  /* Array of auxiliary ELF variables of length auxc */
    int host_import_envc; /* Length of host_import_envp */
    char** host_import_envp; /* Names of environment variables to import from
                                the host */
    exit_status_mode_t exit_status; /* Enclave exit status behaviour */
    size_t num_disks;               /* Length of disks */
    sgxlkl_enclave_disk_config_t*
        disks;        /* Array of disk configurations of length num_disks */
    size_t num_peers; /* Length of peers */
    sgxlkl_enclave_wg_peer_config_t*
        peers; /* Array of wireguard peer configurations of length num_peers */
    sgxlkl_app_size_config_t sizes;
} sgxlkl_app_config_t;

typedef struct sgxlkl_enclave_config
{
    int mode;

    /* Network */
    char* net_ip4;
    char* net_gw4;
    int net_mask4;
    char hostname[32];
    bool hostnet;
    int tap_mtu;
    sgxlkl_enclave_wg_config_t wg;

    /* Scheduling */
    size_t ethreads;
    size_t max_user_threads;
    size_t espins;
    size_t esleep;
    struct timespec clock_res[8];

    /* Various */
    size_t stacksize;
    enclave_mmap_files_t mmap_files;
    size_t oe_heap_pagecount;
    bool fsgsbase;
    bool verbose;
    bool kernel_verbose;
    char* kernel_cmd;
    char* sysctl;
    bool swiotlb; /* Option to toggle swiotlb in SW mode */

    /* Application */
    sgxlkl_app_config_t app_config;
} sgxlkl_enclave_config_t;

#define DEFAULT_SGXLKL_VERBOSE 0
#define DEFAULT_SGXLKL_CWD "/"
#define DEFAULT_SGXLKL_GW4 "10.0.1.254"
/* The default heap size will only be used if no heap size is specified and
 * either we are in simulation mode, or we are in HW mode and a key is provided
 * via SGXLKL_KEY.
 */
#define DEFAULT_SGXLKL_OE_HEAP_PAGE_COUNT 8192 /* 8192 * 4K = 32MB */
#define DEFAULT_SGXLKL_HEAP_SIZE 200 * 1024 * 1024
#define DEFAULT_SGXLKL_HOSTNAME "lkl"
#define DEFAULT_SGXLKL_IP4 "10.0.1.1"
#define DEFAULT_SGXLKL_MASK4 24
#define DEFAULT_SGXLKL_MAX_USER_THREADS 256
#define DEFAULT_SGXLKL_ESLEEP 16000
#define DEFAULT_SGXLKL_ETHREADS 1
#define DEFAULT_SGXLKL_ESPINS 500
#define DEFAULT_SGXLKL_STACK_SIZE 512 * 1024
#define DEFAULT_SGXLKL_SWIOTLB 1
#define DEFAULT_SGXLKL_TAP "sgxlkl_tap0"
#define DEFAULT_SGXLKL_WG_IP "10.0.2.1"
#define DEFAULT_SGXLKL_WG_PORT 56002
#define DEFAULT_SGXLKL_KERNEL_CMD "mem=32M"
#define DEFAULT_SGXLKL_HOSTNET false
#define DEFAULT_SGXLKL_TAP_MTU 0

#define MAX_SGXLKL_ETHREADS 1024
#define MAX_SGXLKL_MAX_USER_THREADS 65536

bool is_encrypted(const sgxlkl_enclave_disk_config_t* disk);

extern const sgxlkl_enclave_config_t sgxlkl_default_enclave_config;

void sgxlkl_free_enclave_config(sgxlkl_enclave_config_t* enclave_config);

#endif /* SGXLKL_ENCLAVE_CONFIG_H */