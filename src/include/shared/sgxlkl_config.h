#ifndef SGXLKL_CONFIG_H
#define SGXLKL_CONFIG_H

#include <elf.h>
#include "host/timer_dev.h"
#include "mpmc_queue.h"
#include "shared/vio_event_channel.h"
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

typedef struct enclave_disk_config
{
    /* Provided by sgx-lkl-run at runtime. */
    int fd;
    size_t capacity;
    char* mmap;
    int create;  // create dynamically?
    size_t size; // size used when create==true
    int enc;     // Encrypted?
    /* Provided by user via sgx-lkl-run config together with the host file
     * system path. */
    char mnt[SGXLKL_DISK_MNT_MAX_PATH_LEN + 1]; // "/" for root disk
    /* Provided by user at runtime (after remote attestation). */
    int ro;                 // Read-only?
    char* key;              // Encryption key
    size_t key_len;         // Key length
    char* roothash;         // Root hash (for dm-verity)
    size_t roothash_offset; // Merkle tree offset (for dm-verity)
    /* Used at runtime */
    int mounted; // Has been mounted

    /* Shared memory between guest & host for virtio block device */
    void* virtio_blk_dev_mem;
} enclave_disk_config_t;

typedef struct enclave_wg_peer_config
{
    char* key;
    char* allowed_ips;
    char* endpoint;

} enclave_wg_peer_config_t;

typedef struct enclave_wg_config
{
    uint32_t ip;
    uint16_t listen_port;
    char* key;
    size_t num_peers;
    enclave_wg_peer_config_t* peers;
} enclave_wg_config_t;

typedef struct sgxlkl_shared_memory
{
    void* shm_common;
    void* shm_enc_to_out;
    void* shm_out_to_enc;

    void* vvar;

    /* shared memory between host & guest for virtio implementation */
    void* virtio_net_dev_mem; /* shared memory for virtio network device */
    void* virtio_console_mem; /* shared memory for virtio console device */
    size_t evt_channel_num;   /* number of event channels */
    enc_dev_config_t* enc_dev_config; /* Device configuration for guest */
    void* virtio_swiotlb;             /* memory for setting up bounce buffer */
    size_t virtio_swiotlb_size;       /* bounce buffer size */
    int enable_swiotlb;               /* Option to toggle swiotlb in SW mode */

    /* shared memory for getting time from the host  */
    struct timer_dev* timer_dev_mem;
} sgxlkl_shared_memory_t;

/* Configuration for SGX-LKL enclave from host */
typedef struct sgxlkl_config
{
    size_t max_user_threads;
    size_t stacksize;
    size_t num_disks;
    enclave_disk_config_t*
        disks;      /* Array of disk configurations, length = num_disks */
    int mmap_files; /* ENCLAVE_MMAP_FILES_{NONE, SHARED, or PRIVATE} */
    int net_fd;
    unsigned int oe_heap_pagecount;
    uint32_t net_ip4;
    uint32_t net_gw4;
    int net_mask4;
    char hostname[32];
    int hostnet;
    int tap_offload;
    int tap_mtu;
    enclave_wg_config_t wg;
    char** argv;
    int argc;
    Elf64_auxv_t* auxv;
    char* cwd;

    exit_status_mode_t
        exit_status; /* Report exit status of process from inside enclave? */

    size_t espins;
    size_t esleep;
    long sysconf_nproc_conf;
    long sysconf_nproc_onln;
    struct timespec clock_res[8];

    int mode;
    int fsgsbase; /* Can we use FSGSBASE instructions within the enclave? */
    int verbose;
    int kernel_verbose;
    char* kernel_cmd;
    char* sysctl;

    char* app_config_str;

    sgxlkl_shared_memory_t shared_memory;
} sgxlkl_config_t;

#endif /* SGXLKL_CONFIG_H */
