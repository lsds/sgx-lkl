#ifndef SGXLKL_ENCLAVE_CONFIG_GEN_H
#define SGXLKL_ENCLAVE_CONFIG_GEN_H

/* Automatically generated from ../../tools/schemas/enclave-config.schema.json; do not modify. */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <elf.h>

#define SGXLKL_ENCLAVE_CONFIG_VERSION 1UL

typedef enum
{
    UNKNOWN_MODE = 0,
    SW_DEBUG_MODE = 1,
    HW_DEBUG_MODE = 2,
    HW_RELEASE_MODE = 3
} sgxlkl_enclave_mode_t;

const char* sgxlkl_enclave_mode_t_to_string(sgxlkl_enclave_mode_t e);
sgxlkl_enclave_mode_t string_to_sgxlkl_enclave_mode_t(const char *e);

typedef enum
{
    ENCLAVE_MMAP_FILES_NONE = 0,
    ENCLAVE_MMAP_FILES_PRIVATE = 1,
    ENCLAVE_MMAP_FILES_SHARED = 2
} sgxlkl_enclave_mmap_files_t;

const char* sgxlkl_enclave_mmap_files_t_to_string(sgxlkl_enclave_mmap_files_t e);
sgxlkl_enclave_mmap_files_t string_to_sgxlkl_enclave_mmap_files_t(const char *e);

typedef enum
{
    EXIT_STATUS_FULL = 0,
    EXIT_STATUS_BINARY = 1,
    EXIT_STATUS_NONE = 2
} sgxlkl_exit_status_mode_t;

const char* sgxlkl_exit_status_mode_t_to_string(sgxlkl_exit_status_mode_t e);
sgxlkl_exit_status_mode_t string_to_sgxlkl_exit_status_mode_t(const char *e);

typedef struct sgxlkl_clock_res_config
{
    char resolution[17];
} sgxlkl_clock_res_config_t;

typedef struct sgxlkl_enclave_disk_config
{
    char mnt[256];
    size_t key_len;
    uint8_t* key;
    char* key_id;
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
    uint32_t listen_port;
    char* key;
    size_t num_peers;
    sgxlkl_enclave_wg_peer_config_t* peers;
} sgxlkl_enclave_wg_config_t;

typedef struct sgxlkl_image_sizes_config
{
    uint64_t num_heap_pages;
    uint64_t num_stack_pages;
} sgxlkl_image_sizes_config_t;

typedef struct sgxlkl_enclave_config
{
    sgxlkl_enclave_mode_t mode;
    char* net_ip4;
    char* net_gw4;
    char* net_mask4;
    char hostname[32];
    bool hostnet;
    uint32_t tap_mtu;
    sgxlkl_enclave_wg_config_t wg;
    size_t ethreads;
    size_t max_user_threads;
    size_t espins;
    size_t esleep;
    sgxlkl_clock_res_config_t clock_res[8];
    size_t stacksize;
    sgxlkl_enclave_mmap_files_t mmap_files;
    size_t oe_heap_pagecount;
    bool fsgsbase;
    bool verbose;
    bool kernel_verbose;
    char* kernel_cmd;
    char* sysctl;
    bool swiotlb;
    char* cwd;
    size_t num_args;
    char** args;
    size_t num_env;
    char** env;
    size_t num_auxv;
    Elf64_auxv_t* auxv;
    size_t num_host_import_env;
    char** host_import_env;
    sgxlkl_exit_status_mode_t exit_status;
    size_t num_disks;
    sgxlkl_enclave_disk_config_t* disks;
    sgxlkl_image_sizes_config_t image_sizes;
} sgxlkl_enclave_config_t;

extern const sgxlkl_enclave_config_t sgxlkl_default_enclave_config;

typedef struct {
    char* scope;
    char* type;
    char* description;
    char* default_value;
    char* override_var;
} sgxlkl_enclave_setting_t;

extern const sgxlkl_enclave_setting_t sgxlkl_enclave_settings[44];

#endif /* SGXLKL_ENCLAVE_CONFIG_H */