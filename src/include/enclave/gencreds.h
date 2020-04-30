#ifndef _ENCLAVE_GENCREDS_H
#define _ENCLAVE_GENCREDS_H

#include <stddef.h>

#define SGXLKL_ATTESTED_CERT_PATH "/run/sgxlkl_cert.der"
#define SGXLKL_ATTESTED_PRIVATE_KEY_PATH "/run/sgxlkl_private_key.pem"

int sgxlkl_generate_attested_credentials(void);

#endif /* _ENCLAVE_GENCREDS_H */
