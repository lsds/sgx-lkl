#ifndef CLIENT_AGENT_INIT_H
#define CLIENT_AGENT_INIT_H

#include <mbedtls/net_sockets.h>
#include "../common/message.h"
#include "tlscli.h"

// The state object shared by sgx-lkl and oe enclave
typedef struct struct_clientAgentState {
    mbedtls_net_context untrustedChannel;
    tlscli_t* trustedChannel ;

    // The current query object (received from oe enclave but not processed yet)
    Query_t* curQuery;


    KeyRelease_t* curRelease;
} ClientAgentState_t;

// Client Agent initializer
ClientAgentState_t* clientAgent_init();

// Clean up Client Agent, including channels.
void clientAgent_free(ClientAgentState_t* state);

#endif // CLIENT_AGENT_INIT_H

