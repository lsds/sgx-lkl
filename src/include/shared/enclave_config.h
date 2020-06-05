#ifndef SGXLKL_ENCLAVE_CONFIG_T_H
#define SGXLKL_ENCLAVE_CONFIG_T_H

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

typedef enum exit_status_mode
{
    EXIT_STATUS_FULL = 0, /* return true_exit_status */
    EXIT_STATUS_BINARY,   /* return true_exit_status ==  0 ? 0 : 1 */
    EXIT_STATUS_NONE      /* return 0 */
} exit_status_mode_t;

typedef struct sgxlkl_enclave_disk_config
{
    char mnt[SGXLKL_DISK_MNT_MAX_PATH_LEN + 1];
    char* key;
    char* key_id;
    size_t key_len;
    bool fresh_key;
    char* roothash;
    size_t roothash_offset;
    bool readonly;
    bool create;
    size_t size;
} sgxlkl_enclave_disk_config_t;

typedef struct sgxlkl_enclave_wg_peer_config
{
    char* key;
    char* allowed_ips;
    char* endpoint;
} sgxlkl_enclave_wg_peer_config_t;

typedef struct sgxlkl_enclave_wg_config
{
    uint32_t ip;
    uint16_t listen_port;
    char* key;
    size_t num_peers;
    sgxlkl_enclave_wg_peer_config_t* peers;
} sgxlkl_enclave_wg_config_t;

typedef struct sgxlkl_app_config
{
    char* run; /* Will ultimately point at the same location as argv[0] */
    char* cwd; /* Working directory */
    int argc;
    char** argv; /* Array of application arguments of length argc */
    int envc;
    char** envp; /* Array of environment variables of length envc */
    int auxc;
    Elf64_auxv_t** auxv; /* Array of auxiliary ELF variables */
    exit_status_mode_t
        exit_status; /* Report exit status of process from inside enclave? */
    size_t num_disks;
    sgxlkl_enclave_disk_config_t*
        disks; /* Array of disk configurations of length num_disks */
    size_t num_peers;
    sgxlkl_enclave_wg_peer_config_t*
        peers; /* Array of wireguard peer configurations of length num_peers */
} sgxlkl_app_config_t;

typedef struct sgxlkl_enclave_config
{
    size_t max_user_threads;
    size_t stacksize;
    int mmap_files;
    int net_fd;
    unsigned int oe_heap_pagecount;
    uint32_t net_ip4;
    uint32_t net_gw4;
    int net_mask4;
    char hostname[32];
    int hostnet;
    int tap_offload;
    int tap_mtu;

    size_t espins;
    size_t esleep;
    long sysconf_nproc_conf;
    long sysconf_nproc_onln;
    struct timespec clock_res[8];

    int mode;
    bool fsgsbase;
    bool verbose;
    bool kernel_verbose;
    char* kernel_cmd;
    char* sysctl;

    bool swiotlb; /* Option to toggle swiotlb in SW mode */

    sgxlkl_app_config_t app_config;
    sgxlkl_enclave_wg_config_t wg;
} sgxlkl_enclave_config_t;

int parse_sgxlkl_app_config_from_str(
    const char* str,
    sgxlkl_app_config_t* conf,
    char** err);

void sgxlkl_default_enclave_config(sgxlkl_enclave_config_t* enclave_config);

void sgxlkl_free_enclave_config(sgxlkl_enclave_config_t* enclave_config);

#endif /* SGXLKL_ENCLAVE_CONFIG_H */