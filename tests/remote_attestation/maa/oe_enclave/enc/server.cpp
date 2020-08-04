#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>
#include <openenclave/enclave.h>


#include <stdlib.h>
#include <string>
#include <assert.h>
#include <sys/socket.h>
#include <map>
#include "../../../common/log_utils.h"
#include "../../../common/transport_utils.h"
#include "tlssrv.h"
#include "oeApp_t.h"

#define MRENCLAVE_SIZE 32
#define MRSIGNER_SIZE 32
#define ISVPRODID_SIZE 16
#define BUFSIZE 32

using namespace std;

extern "C"
{
    int setup_tls_server(const char* server_port);
};

static mbedtls_net_context client_fd;
static tlssrv_t* tlsServer = NULL;
static tlssrv_err_t tlsError;
uint8_t iv[16] = 
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};


static oe_result_t verifier(
    void* arg,
    const uint8_t* mrenclave,
    size_t mrenclave_size,
    const uint8_t* mrsigner,
    size_t mrsigner_size,
    const uint8_t* isvprodid,
    size_t isvprodid_size,
    uint64_t isvsvn)
{
    return OE_OK;
}

int setup_tls_server(const char* server_port)
{
    int rc = 1;
    oe_result_t result = OE_FAILURE;
    mbedtls_net_context listen_fd;
    
    // Explicitly enabling features
    if ((result = oe_load_module_host_resolver()) != OE_OK) {
        printf("oe_load_module_host_resolver failed with %s\n",
            oe_result_str(result));
        goto exit;
    }

    if ((result = oe_load_module_host_socket_interface()) != OE_OK) {
        printf("oe_load_module_host_socket_interface failed with %s\n",
            oe_result_str(result));
        goto exit;
    }

    // Using trusted channel
    if ((rc = tlssrv_startup(&tlsError)) != 0) {
        printf( " failed! tlssrv_startup returned %d\n\n", rc);
        goto exit;
    }

    if ((rc = tlssrv_create(NULL, server_port, verifier, NULL, &tlsServer, &tlsError)) != 0) {
        printf( " failed! tlssrv_create returned %d\n\n", rc);
        goto exit;
    }

    printf( "\n Server in enclave: Waiting for a trusted connection\n");
    fflush( stdout );

    // Wait for a single connections
    if ((rc = tlssrv_accept(tlsServer, &client_fd, &tlsError)) != 0) {
        printf( " failed! tlssrv_accept returned %d\n\n", rc);
        goto exit;
    }

    // Allow time out
    mbedtls_ssl_set_bio(&tlsServer->ssl, &client_fd,
                     mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
    rc = 0;

    printf( " Remote connection established. Ready for service.\n");

exit:
    return rc;
}
