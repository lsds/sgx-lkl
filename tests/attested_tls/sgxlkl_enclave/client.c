// Copyright Microsoft. 
// Licensed under the attached Microsoft Software License Terms

/***************************************************************************
  This is the entry point of sgxlkl_enclave which is responsible for:

  1) Establishing a trusted channel with oe_enclave via clientAgent;
  2) Verify the pregenerated cert (type = 1)

 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include "tlscli.h"
#include "clientAgent.h"
#include "../common/settings.h"
#include "../common/message.h"

// TODO: will cover the cert generation part in the future
#define TLS_CERT_PATH "./sgxlkl_cert.der"
#define TLS_PKEY_PATH "./sgxlkl_private_key.pem"

static tlscli_err_t tlsError;

clientAgentState_t* clientAgent_init(const char* serverIP) {
    int rc;
    clientAgentState_t* state = calloc(1, sizeof(clientAgentState_t));

    if (USE_UNTRUSTED_CHANNEL) {
        mbedtls_net_init(&state->untrustedChannel);
        if ((rc = mbedtls_net_connect(&state->untrustedChannel, serverIP,
              SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
            printf("client Agent: failed to initialize untrusted channel at port "\
               "%s, error code: %d\n", SERVER_PORT, rc);
            goto fail;
        }
    }
    else {
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
