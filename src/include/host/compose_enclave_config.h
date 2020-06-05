#ifndef COMPOSE_ENCLAVE_CONFIG_H
#define COMPOSE_ENCLAVE_CONFIG_H

#include <shared/host_state.h>
#include <shared/sgxlkl_enclave_config.h>

void compose_enclave_config(
    const sgxlkl_host_state_t* host_state,
    const sgxlkl_app_config_t* app_config,
    char** buffer,
    size_t* buffer_size);

#endif /* COMPOSE_ENCLAVE_CONFIG_H */