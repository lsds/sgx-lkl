#ifndef SGXLKL_HOST_CONFIG_H
#define SGXLKL_HOST_CONFIG_H

#include "host/sgxlkl_host_config_gen.h"

/* Read host config (from string) */
int sgxlkl_read_host_config(
    char* from,
    sgxlkl_host_config_t* config,
    char** err);

/* Read host config from file */
int sgxlkl_read_host_config_from_file(
    const char* path,
    sgxlkl_host_config_t* config,
    char** err);

/* Check for environment variable overrides */
bool sgxlkl_config_overridden(const char* key);

/* Retrieve overriding values */
int sgxlkl_config_bool(const char* key);
uint64_t sgxlkl_config_uint64(const char* key);
char* sgxlkl_config_str(const char* key);

#endif /* SGXLKL_HOST_CONFIG_H */