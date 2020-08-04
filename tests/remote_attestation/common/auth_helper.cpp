#include "auth_helper.h"

#include <stdio.h>
#include <string.h>

#include "curl_helper.h"
#include "json_utils.h"
#include "log_utils.h"

// CURL request to get an OAUTH2 auth token
int get_authentication_token(
    const char* app_id,
    const char* client_id,
    const char* client_secret,
    const char* app_url,
    char** authentication_token)
{
    struct curl_buffer bufdata = {0};
    int return_value = -1;
    char url[200];
    char* token = NULL;

    printf("\n\n----GETTING OAUTH2 TOKEN FOR %s----\n\n", app_url);

    // Create URL
    strcpy(url, "https://login.windows.net/");
    strcat(url, app_id);
    strcat(url, "/oauth2/token");

    // Create body
    strcpy(bufdata.send_data, "grant_type=client_credentials&client_id=");
    strcat(bufdata.send_data, client_id);
    strcat(bufdata.send_data, "&client_secret=");
    strcat(bufdata.send_data, client_secret);
    strcat(bufdata.send_data, "&resource=");
    strcat(bufdata.send_data, app_url);
    bufdata.send_data_size = strlen(bufdata.send_data);

    // Send request, get response
    return_value =
        send_receive_curl(url, NULL, 0, send_type_post, &bufdata);
    if (return_value != 0)
    {
        printf(FAILMSG("Failed to send/receive authentication request\n"));
        goto error;
    }
    if (bufdata.response_code != 200)
    {
        printf(
            FAILMSG("OAUTH2 authentication failed, response_code=%ld, [%s]\n"),
            bufdata.response_code,
            bufdata.recv_data);
        return_value = -1;
        goto error;
    }

    // Extract access token
    token = get_json_field_value(bufdata.recv_data, "access_token");
    if (token == NULL)
    {
        printf(FAILMSG(
            "Failed to extract access_token from authentication response\n"));
        return_value = -1;
        goto error;
    }
    *authentication_token = strdup(token);
    if (authentication_token == NULL)
    {
        printf(FAILMSG(
            "Failed to duplicate authentication token from response\n"));
        return_value = -1;
        goto error;
    }

    printf(
        SUCCESSMSG("\nOAUTH2 authentication token for [%s]: success\n"), app_url);

    return_value = 0;

error:
    return return_value;
}
