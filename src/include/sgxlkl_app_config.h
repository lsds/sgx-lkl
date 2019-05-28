#ifndef SGXLKL_APP_CONFIG_H
#define SGXLKL_APP_CONFIG_H

#include "sgx_enclave_config.h"

typedef struct sgxlkl_app_config {
    const char *run; /* Will ultimately point at the same location as argv[0] */
    int argc;
    char **argv; /* Array of application arguments of length argc */
    char **envp; /* Null-terminated array of environment variables */
    size_t num_disks;
    enclave_disk_config_t *disks; /* Array of disk configurations of length num_disks */
    size_t num_peers;
    enclave_wg_peer_config_t *peers; /* Array of wireguard peer configurations of length num_peers */
} sgxlkl_app_config_t;

int parse_sgxlkl_app_config_from_str(char *str, sgxlkl_app_config_t *conf, char **err);

#endif /* SGXLKL_APP_CONFIG_H */
