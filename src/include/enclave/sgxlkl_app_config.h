#ifndef SGXLKL_APP_CONFIG_H
#define SGXLKL_APP_CONFIG_H

#include "shared/sgxlkl_config.h"

typedef struct sgxlkl_app_disk_config
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
} sgxlkl_app_disk_config_t;

typedef struct sgxlkl_app_config
{
    char* run; /* Will ultimately point at the same location as argv[0] */
    char* cwd; /* Working directory */
    int argc;
    char** argv; /* Array of application arguments of length argc */
    int envc;
    char** envp; /* Array of environment variables of length envc */
    size_t num_disks;
    sgxlkl_app_disk_config_t*
        disks; /* Array of disk configurations of length num_disks */
    size_t num_peers;
    enclave_wg_peer_config_t*
        peers; /* Array of wireguard peer configurations of length num_peers */
} sgxlkl_app_config_t;

int parse_sgxlkl_app_config_from_str(
    const char* str,
    sgxlkl_app_config_t* conf,
    char** err);

int validate_sgxlkl_app_config(sgxlkl_app_config_t* config);

#endif /* SGXLKL_APP_CONFIG_H */
