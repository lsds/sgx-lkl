#ifndef SGXLKL_ENCLAVE_CONFIG_H
#define SGXLKL_ENCLAVE_CONFIG_H

#include "shared/enclave_config.h"
#include "shared/sgxlkl_config.h"

/* Indicates different states during sgxlkl startup sequence */
enum sgxlkl_libc_state
{
    libc_not_started = 0,
    libc_initializing = 1,
    libc_initialized = 2
};

extern sgxlkl_enclave_config_t* sgxlkl_enclave;

int sgxlkl_copy_config(const sgxlkl_config_t* from, sgxlkl_config_t** to);
int sgxlkl_free_config(sgxlkl_enclave_config_t* config);

#endif /* SGXLKL_CONFIG_H */
