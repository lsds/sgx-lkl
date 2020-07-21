// Copyright Microsoft. 
// Licensed under the attached Microsoft Software License Terms

#ifndef CLIENT_AGENT_INIT_H
#define CLIENT_AGENT_INIT_H

#include <mbedtls/net_sockets.h>
#include "tlscli.h"

// The state object shared by server and client Agent
typedef struct struct_clientAgentState {
    mbedtls_net_context untrustedChannel;
    tlscli_t* trustedChannel ;
} clientAgentState_t;

#endif