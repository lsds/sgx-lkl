#include <openenclave/host.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "oeApp_u.h"

// The port CLIENT enclave listens on, and SgxLkl App connects to.
#define SERVER_PORT               "13999"

static oe_enclave_t* enclave = NULL;

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_OK;
    int ret = 0;
    int ecall_ret = -1;
    const char* enclave_path = NULL;

    /* Check argument count */
    if (argc != 2) {
        printf("Usage: %s OEAPP_ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    enclave_path = argv[1];
    printf("Host: Enclave path = %s, server port = %s\n", enclave_path, SERVER_PORT);

    result = oe_create_oeApp_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (enclave == NULL || result != OE_OK) {
        printf("Host: Enclave creation failed\n");
        goto exit;
    }

    printf("Host: starting_server\n");
    ret = setup_tls_server(enclave, &ecall_ret, SERVER_PORT);
    if (ecall_ret != 0) {
        printf("Host: setup_tls_server failed with ecall return val: %d\n", ecall_ret);
        ret = -1;
        goto exit;
    }

    // Sleep 120 seconds to give time to sgxlkl enclave app to start up and connect
    sleep(120);

exit:
   if (enclave)
       ret = oe_terminate_enclave(enclave);
    printf("Host: oe_enclave app exited successfully\n");
    return ret;
}
