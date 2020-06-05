#ifndef READ_ENCLAVE_CONFIG_H
#define READ_ENCLAVE_CONFIG_H

#include "shared/sgxlkl_enclave_config.h"

int sgxlkl_read_enclave_config(const char* from, sgxlkl_enclave_config_t** to);

#endif /* READ_ENCLAVE_CONFIG_H */
