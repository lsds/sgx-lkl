#ifndef SGXLKL_ENCLAVE_CONFIG_JSON_H
#define SGXLKL_ENCLAVE_CONFIG_JSON_H

#include "shared/enclave_config.h"

int sgxlkl_read_config_json(const char* from, sgxlkl_enclave_config_t** to);

#endif /* SGXLKL_ENCLAVE_CONFIG_JSON_H */
