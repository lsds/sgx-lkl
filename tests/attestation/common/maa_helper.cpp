#include "maa_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth_helper.h"
#include "curl_helper.h"
#include "json_utils.h"
#include "log_utils.h"

static int get_maa_token(
    const char* authentication_token,
    const char* report_base64url,
    const char* private_data_base64url,
    char** maa_token)
{
    struct curl_buffer bufdata = {0};
    int return_value = -1;

    const char* url = getenv("MAA_ADDR");
    char token[20480];
    sprintf(token, "Authorization: Bearer %s", authentication_token);
    const char* header[] = {"Content-Type: application/json", token};

    printf("\n\n----GETTING MAA TOKEN USING OAUTH2 TOKEN----%s\n\n", url);

    sprintf(
        bufdata.send_data,
        "{\"Quote\":\"%s\",\"EnclaveHeldData\":\"%s\"}",
        report_base64url,
        private_data_base64url);
    bufdata.send_data_size = strlen(bufdata.send_data);

    return_value = send_receive_curl(
        url,
        header,
        sizeof(header) / sizeof(header[0]),
        send_type_post,
        &bufdata);
    if (return_value != 0)
    {
        printf(FAILMSG("Failed to send/receive authentication request\n"));
        goto error;
    }

    if (bufdata.response_code != 200)
    {
        printf(
            FAILMSG("MAA token retrieval failed, response_code=%ld, [%s]\n"),
            bufdata.response_code,
            bufdata.recv_data);
        return_value = -1;
        goto error;
    }

    *maa_token = strdup(bufdata.recv_data);
    if (*maa_token == NULL)
    {
        printf(FAILMSG("Failed to duplicate MAA JWT Token\n"));
        return_value = -1;
        goto error;
    }

    printf(SUCCESSMSG("\nMAA JWT token obtained\n"));

    return_value = 0;

error:
    return return_value;
}

int authenticate_and_get_maa_token(
    const char* app_id,
    const char* client_id,
    const char* client_secret,
    const char* report_base64url,
    const char* enclave_private_data_base64url,
    char** maa_token)
{
    int ret = -1;
    char* maa_authentication_token = NULL;

    ret = get_authentication_token(
        app_id,
        client_id,
        client_secret,
        getenv("MAA_ADDR_APP"),
        &maa_authentication_token);
    if (ret != 0)
    {
        printf(FAILMSG("Failed to get MAA authentication token\n"));
        goto done;
    }

    ret = get_maa_token(
        maa_authentication_token,
        report_base64url,
        enclave_private_data_base64url,
        maa_token);
    if (ret != 0)
    {
        printf(FAILMSG("Failed to get MAA token\n"));
        goto done;
    }

done:
    return ret;
}
