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
#include "../../common/message.h"
#include "../../common/log_utils.h"
#include "../../common/transport_utils.h"
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
    int run_server(void* ptr);
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
    const uint64_t SGXLKL_ISVSVN = 1;
    const uint8_t SGXLKL_ISVPRODID[ISVPRODID_SIZE] = {1};
    const uint64_t OE_ISVSVN = 3;
    const uint8_t OE_ISVPRODID[ISVPRODID_SIZE] = {2};
    // clang-format off

    // SGX-LKL Debug MRSIGNER
    const uint8_t SGXLKL_MRSIGNER[] =
    {
        0x33, 0x17, 0x34, 0x4b, 0xfa, 0xe6, 0x25, 0x43,
        0x4d, 0x8c, 0x63, 0xe6, 0x45, 0xd5, 0x01, 0xe9,
        0xfb, 0x85, 0xec, 0x02, 0xbc, 0x34, 0x99, 0x3b,
        0x75, 0xe6, 0x47, 0x93, 0x08, 0x75, 0x77, 0xf4
    };

    // OE SDK Debug MRSIGNER
    const uint8_t OE_MRSIGNER[] =
    {
        0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a,
        0xa2, 0x88, 0x90, 0xce, 0x73, 0xe4, 0x33, 0x63,
        0x83, 0x77, 0xf1, 0x79, 0xab, 0x44, 0x56, 0xb2,
        0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0x0a
    };

    // clang-format on

    (void)arg;

    if (!mrenclave || !mrsigner || !isvprodid)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (mrenclave_size != MRENCLAVE_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (mrsigner_size != MRSIGNER_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    if (isvprodid_size != ISVPRODID_SIZE)
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    printf("\n");
    printf("=== _verify_identity()\n");
    log_hex_data("MRENCLAVE", mrenclave, mrenclave_size);
    log_hex_data("MRSIGNER", mrsigner, mrsigner_size);
    log_hex_data("ISVPRODID", isvprodid, isvprodid_size);
    printf("ISVSVN: %lu\n", isvsvn);
    printf("\n");

    if (memcmp(mrsigner, SGXLKL_MRSIGNER, MRSIGNER_SIZE) == 0)
    {
        if (memcmp(isvprodid, SGXLKL_ISVPRODID, ISVPRODID_SIZE) != 0)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
        if (isvsvn != SGXLKL_ISVSVN)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
    }
    // TODO: SgxLkl App takes OE debug identity when running without SGX-LKL.
    // Allow OE debug identity to be used only in debug mode of OEAPP.
    else if (memcmp(mrsigner, OE_MRSIGNER, MRSIGNER_SIZE) == 0)
    {
        if (memcmp(isvprodid, OE_ISVPRODID, ISVPRODID_SIZE) != 0)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
        if (isvsvn != OE_ISVSVN)
        {
            fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
            return OE_VERIFY_FAILED;
        }
    }
    else
    {
        fprintf(stderr, "_verify_identity() failed: line %d\n", __LINE__);
        return OE_VERIFY_FAILED;
    }

    return OE_OK;
}

// Handling key requests from SgxLkl App and queries from OEAPP host.
int run_server(void* ptr) {
    int rc = 1;
    tlssrv_t* srv = NULL;
    tlssrv_err_t err;
    size_t msize = sizeof(Message_t);
    Message_t message;
    unsigned char * buf = (unsigned char*)&message;

    // TODO: check if ptr is outside enclave
    Query_t* query = (Query_t*)ptr;
    while (1) {
        // check termination condition
        if (__atomic_load_n(&query->allDone, __ATOMIC_SEQ_CST) == 1) {
            break;
        }

        // Check if there is a new query. If yes, send it to SgxLkl App.
        if (__atomic_load_n(&query->sent, __ATOMIC_SEQ_CST) == 0) {
            printf(" Sending query to client\n");
            message.type = MESSAGE_TYPE_QUERY;
            message.u.query = *query;

            rc = USE_UNTRUSTED_CHANNEL ?
                  mbedtls_net_send( &client_fd, buf, msize) :
                  mbedtls_ssl_write(&tlsServer->ssl, buf, msize);
            if (rc != msize) {
                printf( " failed to send query. rc: %d\n\n", rc );
                goto exit;
            }
            __atomic_store_n(&query->sent, 1, __ATOMIC_SEQ_CST);
        }

        // Receive messages from SgxLkl App
        memset(buf, 0, msize);

        // Time out in 0.1 second.
        rc  = USE_UNTRUSTED_CHANNEL ?
                mbedtls_net_recv_timeout( &client_fd, buf, msize, 100) :
                mbedtls_ssl_read(&tlsServer->ssl, buf, msize);

        if (rc > 0) {
            // If a query result, write to a file. Print to screen for now.
            if (message.type == MESSAGE_TYPE_QUERY_RESULT) {
                QueryResult_t* res = &message.u.result;
                assert(res->sequenceID <= res->sequenceCount);
                printf(" ==== Query Result %d/%d ====\n%s\n", res->sequenceID,
                      res->sequenceCount, res->text);
                __atomic_store_n(&query->processed, 1, __ATOMIC_SEQ_CST);
            }
            else {
                printf(" failed! Unknown message type\n");
                assert(0); // shouldn't be here
            }
        }
        else if (rc != MBEDTLS_ERR_SSL_TIMEOUT) {
            printf("  failed to receive message. rc = %d\n", rc);
            goto exit;
        }
    }

    rc = 0;
exit:
    mbedtls_net_free(&client_fd);
    return rc;
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

    if (USE_UNTRUSTED_CHANNEL) {
        mbedtls_net_init( &listen_fd );
        mbedtls_net_init( &client_fd );

        printf( "\n Server in enclave: Waiting for a remote connection\n");
        fflush( stdout );

        if( (rc = mbedtls_net_bind(
                    &listen_fd,
                    NULL, /* accept wildcard ip addresses from client */
                    server_port,
                    MBEDTLS_NET_PROTO_TCP)) != 0){
            printf( " failed! mbedtls_net_bind returned %x\n\n", rc );
            goto exit;
        }

        if( ( rc = mbedtls_net_accept( &listen_fd, &client_fd, NULL, 0, NULL ) ) != 0 ) {
            printf( " failed! mbedtls_net_accept returned %d\n\n", rc );
            goto exit;
        }
    }
    else {
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

        /* Wait for a single connections */
        if ((rc = tlssrv_accept(tlsServer, &client_fd, &tlsError)) != 0) {
            printf( " failed! tlssrv_accept returned %d\n\n", rc);
            goto exit;
        }

        // Allow time out
        mbedtls_ssl_set_bio(&tlsServer->ssl, &client_fd,
                         mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
    }
    rc = 0;

    printf( " Remote connection established. Ready for service.\n");
exit:
    if (USE_UNTRUSTED_CHANNEL) {
        mbedtls_net_free( &listen_fd );
    }
    return rc;
}
