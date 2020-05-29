#ifndef SGXLKL_ENCLAVE_CONFIG_T_H
#define SGXLKL_ENCLAVE_CONFIG_T_H

#include "shared/sgxlkl_config.h"

typedef struct sgxlkl_enclave_disk_config
{
    char mnt[SGXLKL_DISK_MNT_MAX_PATH_LEN + 1];
    char* key;
    char* key_id;
    size_t key_len;
    char* roothash;
    size_t roothash_offset;
    int readonly;
    int create;
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

typedef struct sgxlkl_enclave_config_shared_memory
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

    /* Shared memory between guest & host for virtio block device */
    size_t num_virtio_blk_dev;
    void** virtio_blk_dev_mem;
} sgxlkl_enclave_config_shared_memory_t;

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
    int fsgsbase;
    int verbose;
    int kernel_verbose;
    char* kernel_cmd;
    char* sysctl;

    char* cwd;
    int argc;
    char** argv;
    int envc;
    char** envp;
    int auxc;
    Elf64_auxv_t** auxv;

    exit_status_mode_t exit_status;

    size_t num_disks;
    sgxlkl_enclave_disk_config_t* disks;

    enclave_wg_config_t wg;

    sgxlkl_enclave_config_shared_memory_t shared_memory;
} sgxlkl_enclave_config_t;

#endif /* SGXLKL_ENCLAVE_CONFIG_H */