
/***************************************************************************
  This is the entry point of sgxlkl_enclave which is responsible for:

  1) Establishing a trusted channel with oe_enclave;
  2) Verify the pregenerated cert

 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include "tlscli.h"

// TODO: will cover the cert generation part in the future
#define TLS_CERT_PATH "./sgxlkl_cert.der"
#define TLS_PKEY_PATH "./sgxlkl_private_key.pem"
#define SERVER_PORT "17500"

static tlscli_err_t tlsError;

typedef struct struct_clientAgentState {
    mbedtls_net_context untrustedChannel;
    tlscli_t* trustedChannel ;
} clientAgentState_t;

clientAgentState_t* clientAgent_init(const char* serverIP) {
    int rc;
    clientAgentState_t* state = calloc(1, sizeof(clientAgentState_t));
    
    if ((rc = tlscli_startup(&tlsError)) != 0) {
            printf("client Agent failed! tlscli_startup\n");
            goto fail;
    }

    if ((rc = tlscli_connect(true, serverIP, SERVER_PORT,
                TLS_CERT_PATH, TLS_PKEY_PATH,
                &state->trustedChannel, &tlsError)) != 0) {
        printf("client Agent failed! tlscli_connect with cert file: %s"\
                " and pkey file: %s\n", TLS_CERT_PATH, TLS_PKEY_PATH);
        goto fail;
    }

    return state;

fail:
    free(state);
    mbedtls_net_free(&state->untrustedChannel);
    tlscli_destroy(state->trustedChannel, &tlsError);
    tlscli_shutdown(&tlsError);
    return NULL;
}

void clientAgent_free(clientAgentState_t* state) {
    if (state)
    {
        free(state);
    }
}

int main(int argc, char **argv) {
    int result = 0;
    char* serverIP = NULL;

    if (argc != 2 ) {
        fprintf(stderr, "usage: %s serverIP\n", argv[0]);
        return 1;
    }
    serverIP = argv[1];

    clientAgentState_t* state = clientAgent_init(serverIP);
    if (state == NULL) {
        fprintf(stderr, "server: failed to establish channel\n");
        goto done;
    }

done:
    clientAgent_free(state);
    return result;
}
