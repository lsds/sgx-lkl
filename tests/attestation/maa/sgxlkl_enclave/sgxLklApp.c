/***************************************************************************
  This is the entry point of sgxlkl_enclave which is responsible for:

  1) Establishing a trusted TLS channel with oe_enclave via clientAgent;
  2) Doing remote attestation against MAA. sgxlkl_enclave attests oe_enclave  

 **************************************************************************/

#include <stdio.h>
#include <string.h>
#include "clientAgent_init.h"

int main(int argc, char **argv) {
    int result = 0;
    char* action = NULL;
    char* serverIP = NULL;

    if (argc != 2 ) {
        fprintf(stderr, "usage: %s serverIP\n", argv[0]);
        return 1;
    }
    serverIP = argv[1];

    ClientAgentState_t* state = clientAgent_init(serverIP);
    if (state == NULL) {
        fprintf(stderr, "sgxLklApp: failed to establish channel\n");
        goto done;
    }

done:
    clientAgent_free(state);
    return result;
}
