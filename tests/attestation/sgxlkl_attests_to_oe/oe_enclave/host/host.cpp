#include <openenclave/host.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "tlssrv_u.h"

#define SERVER_PORT "17500"

static oe_enclave_t* enclave = NULL;

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_OK;
    int ret = -1;
    int ecall_ret = -1;
    int choice;
    const char* enclave_path = NULL;
    const char* run_mode = NULL;

    /* Check argument count */
    if (argc != 3) {
        printf("Usage: %s TLS_SERVER_ENCLAVE_PATH RUN_MODE\n", argv[0]);
        return 1;
    }

    enclave_path = argv[1];
    run_mode = argv[2];
    printf("Host: Enclave path = %s, Run mode = %s, server port = %s\n", enclave_path, run_mode, SERVER_PORT);

    result = oe_create_tlssrv_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        strcmp(run_mode, "sw") == 0 ? OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE : OE_ENCLAVE_FLAG_DEBUG,
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
    sleep(60);

exit:
    if (enclave)
        ret = oe_terminate_enclave(enclave);

    printf("Host:  %s \n", (ret == 0) ? "oe_enclave app exited successfully" : "oe_enclave app failed");
    return ret;
}