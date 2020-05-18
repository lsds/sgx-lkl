#ifndef SGXLKL_ENCLAVE_CONFIG_JSON_H
#define SGXLKL_ENCLAVE_CONFIG_JSON_H

#include "shared/sgxlkl_config.h"

int sgxlkl_read_config_json(
    const char* from,
    sgxlkl_config_t** to,
    sgxlkl_app_config_t** app_to);

int sgxlkl_read_app_config_json(const char* from, sgxlkl_app_config_t** app_to);

#endif /* SGXLKL_ENCLAVE_CONFIG_JSON_H */
