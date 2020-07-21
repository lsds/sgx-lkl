#ifndef CLIENT_AGENT_MSG_H
#define CLIENT_AGENT_MSG_H

#include <mbedtls/net_sockets.h>
#include "../common/message.h"
#include "tlscli.h"
#include "clientAgent_init.h"


// Try to receive a message from Client. Returning 0 indicates success.
// Time out (no messages received) is considered success.
int clientAgent_receiveMessage(ClientAgentState_t* state);


#endif // CLIENT_AGENT_MSG_H
    
