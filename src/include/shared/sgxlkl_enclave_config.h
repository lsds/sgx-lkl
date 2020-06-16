#ifndef SGXLKL_ENCLAVE_CONFIG_H
#define SGXLKL_ENCLAVE_CONFIG_H

#include <elf.h>
#include <shared/shared_memory.h>
#include <shared/vio_event_channel.h>
#include "host/timer_dev.h"
#include "mpmc_queue.h"
#include "time.h"

#define MAX_SGXLKL_ETHREADS 1024
#define MAX_SGXLKL_MAX_USER_THREADS 65536

typedef enum sgxlkl_enclave_mode
{
    UNKNOWN_MODE = 0,
    SW_DEBUG_MODE = 1,
    HW_DEBUG_MODE = 2,
    HW_RELEASE_MODE = 3
} sgxlkl_enclave_mode_t;

/* Maximum path length of mount points for secondary disks */
#define SGXLKL_DISK_MNT_MAX_PATH_LEN 255
#define SGXLKL_REPORT_NONCE_SIZE 32

typedef enum
{
    ENCLAVE_MMAP_FILES_NONE = 0,
    ENCLAVE_MMAP_FILES_PRIVATE = 1,
    ENCLAVE_MMAP_FILES_SHARED = 2
} sgxlkl_enclave_mmap_files_t;

typedef enum sgxlkl_exit_status_mode
{
    EXIT_STATUS_FULL = 0, /* return true_exit_status */
    EXIT_STATUS_BINARY,   /* return true_exit_status ==  0 ? 0 : 1 */
    EXIT_STATUS_NONE      /* return 0 */
} sgxlkl_exit_status_mode_t;

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
    size_t num_peers; /* Length of peers */
    sgxlkl_enclave_wg_peer_config_t*
        peers; /* Array of wireguard peer configurations of length num_peers */
} sgxlkl_enclave_wg_config_t;

typedef struct sgxlkl_image_sizes_config
{
    uint64_t num_heap_pages;
    uint64_t num_stack_pages;
    uint64_t num_tcs;
} sgxlkl_image_sizes_config_t;

#define SGXLKL_ENCLAVE_CONFIG_VERSION 1UL

typedef struct sgxlkl_enclave_config
{
    sgxlkl_enclave_mode_t mode;

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
    sgxlkl_enclave_mmap_files_t mmap_files;
    size_t oe_heap_pagecount;
    bool fsgsbase;
    bool verbose;
    bool kernel_verbose;
    char* kernel_cmd;
    char* sysctl;
    bool swiotlb; /* Option to toggle swiotlb in SW mode */

    /* Application */
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
    sgxlkl_exit_status_mode_t exit_status; /* Enclave exit status behaviour */

    /* Disks */
    size_t num_disks; /* Length of disks */
    sgxlkl_enclave_disk_config_t*
        disks; /* Array of disk configurations of length num_disks */

    /* Image sizes */
    sgxlkl_image_sizes_config_t image_sizes;
} sgxlkl_enclave_config_t;

extern const sgxlkl_enclave_config_t sgxlkl_default_enclave_config;

int sgxlkl_read_enclave_config(
    const char* from,
    sgxlkl_enclave_config_t* to,
    bool enforce_format);

void sgxlkl_free_enclave_config(sgxlkl_enclave_config_t* enclave_config);

#endif /* SGXLKL_ENCLAVE_CONFIG_H */