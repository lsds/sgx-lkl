#include "enclave/enclave_cert_user.h"
#include <stdio.h>
#include <stdlib.h>

// This function and its caller should be moved to
// user space once we have a clean separation.
int sgxlkl_write_tls_credentials(
    uint8_t* cert,
    size_t cert_size,
    uint8_t* private_key,
    size_t private_key_size,
    const char* cert_path,
    const char* pkey_path)
{
    int ret = -1;

    FILE* os1 = NULL;
    FILE* os2 = NULL;

    if (!(os1 = fopen(cert_path, "wb")))
        goto done;

    if (!(os2 = fopen(pkey_path, "wb")))
        goto done;

    if (fwrite(cert, 1, cert_size, os1) != cert_size)
        goto done;

    if (fwrite(private_key, 1, private_key_size, os2) != private_key_size)
        goto done;

    ret = 0;

done:
    if (os1)
        fclose(os1);

    if (os2)
        fclose(os2);

    return ret;
}