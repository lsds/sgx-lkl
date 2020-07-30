#ifndef _ENCLAVE_CERT_USER_H
#define _ENCLAVE_CERT_USER_H

#include <stddef.h>
#include <stdint.h>

int sgxlkl_write_tls_credentials(
    uint8_t* cert,
    size_t cert_size,
    uint8_t* private_key,
    size_t private_key_size,
    const char* cert_path,
    const char* pkey_path);

#endif /* _ENCLAVE_CERT_USER_H */
