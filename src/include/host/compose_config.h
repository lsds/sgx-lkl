#ifndef SGXLKL_COMPOSE_CONFIG_H
#define SGXLKL_COMPOSE_CONFIG_H

#include <shared/enclave_config.h>
#include <shared/host_state.h>

void compose_enclave_config(
    const sgxlkl_host_state_t* host_state,
    const sgxlkl_app_config_t* app_config,
    char** buffer,
    size_t* buffer_size,
    const char* filename);

#endif /* SGXLKL_COMPOSE_CONFIG_H */