#ifndef SERIALIZE_ENCLAVE_CONFIG_H
#define SERIALIZE_ENCLAVE_CONFIG_H

#include <shared/sgxlkl_enclave_config.h>

void serialize_enclave_config(
    const sgxlkl_enclave_config_t* config,
    char** buffer,
    size_t* buffer_size);

#endif /* SERIALIZE_ENCLAVE_CONFIG_H */