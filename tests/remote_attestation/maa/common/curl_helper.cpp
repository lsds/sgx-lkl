#include "curl_helper.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "log_utils.h"

#define log_curl_error(curl_error, msg)      \
    if (curl_error != CURLE_OK)              \
    {                                        \
        printf(                              \
            FAILMSG("%s, 0x%X, %s\n"),       \
            msg,                             \
            curl_error,                      \
            curl_easy_strerror(curl_error)); \
    }

#define goto_if_curl_error(curl_error, msg, label) \
    if (curl_error != CURLE_OK)                    \
    {                                              \
        log_curl_error(curl_error, msg);           \
        goto label;                                \
    }

// Callback to extract the body of the response.
static size_t response_data_cb(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    struct curl_buffer* bufdata = (struct curl_buffer*)userdata;
    memcpy(&bufdata->recv_data[bufdata->recv_data_size], ptr, size * nmemb);
    bufdata->recv_data_size += size * nmemb;
    bufdata->recv_data[bufdata->recv_data_size] = 0;
    return nmemb * size;
}

int send_receive_curl(
    const char* url,
    const char* request_headers[],
    int request_headers_count,
    send_type operation_type,
    struct curl_buffer* bufdata)
{
    void* curl;
    CURLcode curl_error;
    int return_value = -1;
    struct curl_slist* headers_list = NULL;

    curl = curl_easy_init();
    if (curl)
    {
        // URL
        curl_error = curl_easy_setopt(curl, CURLOPT_URL, url);
        goto_if_curl_error(curl_error, "Failed to set URL option", error);

        // Extra headers
        if (request_headers_count)
        {
            for (int i = 0; i != request_headers_count; i++)
            {
                headers_list =
                    curl_slist_append(headers_list, request_headers[i]);
                if (headers_list == NULL)
                {
                    printf(
                        FAILMSG("Failed to add %s to header list"),
                        request_headers[i]);
                    goto error;
                }
            }
            curl_error =
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers_list);
            goto_if_curl_error(
                curl_error, "Failed to set HTTPHEADER option", error);
        }

        // Operation Request Type
        switch (operation_type)
        {
        case send_type_post:
        {
            curl_error = curl_easy_setopt(curl, CURLOPT_POST, 1L);
            goto_if_curl_error(
                curl_error, "Failed to set POST option", error);
            break;
        }
        case send_type_get:
        {
            curl_error = curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            goto_if_curl_error(
                curl_error, "Failed to set GET option", error);
            break;
        }
        case send_type_delete:
        {
            curl_error =
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            goto_if_curl_error(
                curl_error, "Failed to set DELETE option", error);
            break;
        }
        default:
        {
            printf("Invalid operation type\n");
            goto error;
        }
        }

        // Body
        if (bufdata->send_data_size)
        {
            curl_error =
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bufdata->send_data);
            goto_if_curl_error(
                curl_error, "Failed to set POSTFIELDS option", error);
        }

        // Reponse reader callback
        curl_error =
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_data_cb);
        goto_if_curl_error(
            curl_error, "Failed to set WRITEFUNCTION option", error);
        curl_error = curl_easy_setopt(curl, CURLOPT_WRITEDATA, bufdata);
        goto_if_curl_error(curl_error, "Failed to set WRITEDATA option", error);

        /* Perform the request, res will get the return code */
        curl_error = curl_easy_perform(curl);
        goto_if_curl_error(curl_error, "Failed curl_easy_perform", error);

        // Determine if it is a success or failure response!
        long code;
        curl_error = curl_easy_getinfo(curl, CURLINFO_HTTP_CONNECTCODE, &code);
        if (!curl_error && code)
        {
            printf(FAILMSG("The CONNECT response code: %03ld\n"), code);
            goto error;
        }

        long response_code;
        curl_error =
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        goto_if_curl_error(curl_error, "Failed to get RESPONSE_CODE", error);

        bufdata->response_code = response_code;

        //Success or not_found counted as success
        if (response_code != 200 && response_code != 404)
        {
            printf(
                FAILMSG("Response code while talking to %s: %ld\n"),
                url,
                response_code);
            if (bufdata->recv_data_size)
            {
                printf(FAILMSG("Error response %s\n"), bufdata->recv_data);
            }
            goto error;
        }
    }
    else
    {
        printf(FAILMSG("Failed curl_easy_init\n"));
        goto error;
    }
    return_value = 0;

error:
    if (headers_list)
    {
        curl_slist_free_all(headers_list);
    }
    if (curl)
    {
        curl_easy_cleanup(curl);
    }

    return return_value;
}
