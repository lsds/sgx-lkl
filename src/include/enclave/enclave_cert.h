#ifndef _ENCLAVE_CERT_H
#define _ENCLAVE_CERT_H

#include <stddef.h>
#include <stdint.h>

int enclave_generate_tls_credentials(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out);

#endif /* _ENCLAVE_CERT_H */
