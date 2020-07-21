/***************************************************************************
  OE_ENCLAVE AGENT 
  
  This module mainly interacts with OE_ENCLAVE. It is responsible for:

  1) Establishing a trusted channel with oe_enclave;
  2) Receiving queries from oe enclave;
  3) Returning query results back to oe_enclave;
 **************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include "clientAgent_init.h"
#include "tlscli.h"

#define TLS_CERT_PATH "./sgxlkl_cert.der"
#define TLS_PKEY_PATH "./sgxlkl_private_key.pem"

static tlscli_err_t tlsError;

ClientAgentState_t* clientAgent_init(const char* serverIP) {
    int rc;
    ClientAgentState_t* state = calloc(1, sizeof(ClientAgentState_t));

    //setup Trusted Channel. To be implemented
    if (USE_UNTRUSTED_CHANNEL) {
        mbedtls_net_init(&state->untrustedChannel);
        if ((rc = mbedtls_net_connect(&state->untrustedChannel, serverIP,
              SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
            printf("Client Agent: failed to initialize untrusted channel at port "\
               "%s, error code: %d\n", SERVER_PORT, rc);
            goto fail;
        }
    }
    else {
        if ((rc = tlscli_startup(&tlsError)) != 0) {
                printf("Client Agent failed! tlscli_startup\n");
                goto fail;
        }

        if ((rc = tlscli_connect(true, serverIP, SERVER_PORT,
                  TLS_CERT_PATH, TLS_PKEY_PATH,
                  &state->trustedChannel, &tlsError)) != 0) {
            printf("Client Agent failed! tlscli_connect with cert file: %s"\
                  " and pkey file: %s\n", TLS_CERT_PATH, TLS_PKEY_PATH);
            goto fail;
        }
    }

    return state;

fail:
    free(state);
    mbedtls_net_free(&state->untrustedChannel);
    tlscli_destroy(state->trustedChannel, &tlsError);
    tlscli_shutdown(&tlsError);
    return NULL;
}

void clientAgent_free(ClientAgentState_t* state) {
    if (state)
    {
        if (state->curRelease != NULL) {
            free((unsigned char *)state->curRelease);
        }
        free(state);
    }
}
