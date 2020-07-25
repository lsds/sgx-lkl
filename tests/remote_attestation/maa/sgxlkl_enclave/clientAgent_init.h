#ifndef CLIENT_AGENT_INIT_H
#define CLIENT_AGENT_INIT_H

#include <mbedtls/net_sockets.h>
#include "tlscli.h"

// The state object shared by sgx-lkl and oe enclave
typedef struct struct_clientAgentState {
    mbedtls_net_context untrustedChannel;
    tlscli_t* trustedChannel ;
} ClientAgentState_t;

// Client Agent initializer
ClientAgentState_t* clientAgent_init();

// Clean up Client Agent, including channels.
void clientAgent_free(ClientAgentState_t* state);

#endif // CLIENT_AGENT_INIT_H

