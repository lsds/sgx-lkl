#ifndef CURL_HELPER_H
#define CURL_HELPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    struct curl_buffer
    {
        char send_data[1024 * 20];
        size_t send_data_size;
        char recv_data[1024 * 20];
        size_t recv_data_size;
        long response_code;
    };
    typedef enum
    {
        send_type_post = 1,
        send_type_delete = 2,
        send_type_get = 3
    } send_type;

    int send_receive_curl(
        const char* url,
        const char* request_headers[],
        int request_headers_count,
        send_type operation_type,
        struct curl_buffer* bufdata);

#ifdef __cplusplus
}
#endif

#endif  // CURL_HELPER_H
