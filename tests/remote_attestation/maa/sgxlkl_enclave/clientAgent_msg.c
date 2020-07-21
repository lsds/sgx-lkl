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
#include "clientAgent_msg.h"

int clientAgent_receiveMessage(ClientAgentState_t* state) {
    int rc = 1;
    Message_t message = {0};
    size_t msize = sizeof(Message_t);
    unsigned char * buf = (unsigned char*)&message;

    rc = USE_UNTRUSTED_CHANNEL ?
          mbedtls_net_recv_timeout(&state->untrustedChannel, buf, msize, 100) :
          mbedtls_ssl_read(&state->trustedChannel->ssl, buf, msize);

    if (rc > 0) {
        if (message.type == MESSAGE_TYPE_QUERY) {
            printf("Received query from server\n");
            // wait until the current query is picked up
            while (__atomic_load_n(&state->curQuery, __ATOMIC_SEQ_CST) != NULL);

            Query_t* query = (Query_t*)malloc(sizeof(Query_t));
            if (query == NULL) {
                printf("Client Agent: out of memory\n");
                goto exit;
            }
            memcpy(query, &message.u.query, sizeof(Query_t));
            // Turn on current query so others can handle it.
            __atomic_store_n(&state->curQuery, query, __ATOMIC_SEQ_CST);
        }
        else if (message.type == MESSAGE_TYPE_KEY_RELEASE) {
            printf("Received key from server\n");
            // wait until the current key is picked up
            while (__atomic_load_n(&state->curRelease, __ATOMIC_SEQ_CST) != NULL);

            KeyRelease_t* release = (KeyRelease_t*)malloc(sizeof(KeyRelease_t));
            if (release == NULL) {
                printf("Client Agent: out of memory\n");
                goto exit;
            }

            memcpy(release, &message.u.release, sizeof(KeyRelease_t));
            // Turn on current key release so others can grab it.
            __atomic_store_n(&state->curRelease, release, __ATOMIC_SEQ_CST);
        }
        else
            assert(0); // shouldn't be here.
    }

    if (rc <= 0 && rc != MBEDTLS_ERR_SSL_TIMEOUT) {
        printf("Client Agent: failed to receive message. rc: %d\n", rc);
        rc = 1;
        goto exit;
    }
    rc = 0;
exit:
    return rc;
}
