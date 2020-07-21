#ifndef CLIENT_COMMON_H
#define CLIENT_COMMON_H

#define MESSAGE_TYPE_QUERY        0
#define MESSAGE_TYPE_QUERY_RESULT 1
#define MESSAGE_TYPE_KEY_REQUEST  2
#define MESSAGE_TYPE_KEY_RELEASE  3

// The port CLIENT enclave listens on, and SgxLkl App connects to.
#define SERVER_PORT               "13999"

// The maximum length of a RPC parameter.
#define MAX_PARAM_LEN             64
// The maximum number of parameters in a RPC
#define MAX_PARAM_NUM             16
// The maximum length of RPC result enclosed in one message/
#define MAX_RESULT_LEN            1024
// The maximum key length
#define MAX_KEY_LEN               256
// The maximum length of a key path
#define MAX_KEY_PATH_LEN          512

// Whether we use trusted or untrusted channel
#define USE_UNTRUSTED_CHANNEL 0

// The query object sent from CLIENT to SgxLkl App
typedef struct struct_query {
    // Whether we are done with all queries
    unsigned char allDone;
    // Whether this query has been sent or not
    unsigned char sent;
    // Whether this query has been processed or not
    unsigned char processed;
    // The id of the procedure to be invoked on SgxLkl App
    unsigned short procedureID;
    // Actual number of parameters
    unsigned short numParams;
    // The buffer holds all parameters
    unsigned char params[MAX_PARAM_LEN][MAX_PARAM_NUM];
} Query_t;

// The query result object sent from SgxLkl App to CLIENT
typedef struct struct_query_result {
    // The id of the procedure that is executed
    unsigned short procedureID;
    // The total number of messages in this sequence
    unsigned short sequenceCount;
    // The id of current message in the sequence
    unsigned short sequenceID;
    // The text of the result
    char text[MAX_RESULT_LEN];
} QueryResult_t;

// The key request object sent from SgxLkl App to CLIENT
typedef struct struct_key_request {
    // The actual length of the key
    unsigned char keyLen;
    // Whether the request is for encryption or decryption
    unsigned char forEncryption;
    // The key
    unsigned char keyIn[MAX_KEY_LEN];
    // The path to the master key that is used to encrypt/decrypt the key
    char cmkPath[MAX_KEY_PATH_LEN];
} KeyRequest_t;

// The key release object sent from CLIENT to SgxLkl App
typedef struct struct_key_release {
    unsigned char keyLen;
    unsigned char keyOut[MAX_KEY_LEN];
} KeyRelease_t;

// The message object exchanged between CLIENT and SgxLkl App
typedef struct struct_message {
    char type;
    union {
        Query_t query;
        QueryResult_t result;
        KeyRequest_t request;
        KeyRelease_t release;
    } u;
} Message_t;

#endif // CLIENT_COMMON_H
