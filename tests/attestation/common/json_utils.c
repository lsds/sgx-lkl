#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log_utils.h"

#define FAIL -1
#define SUCCESS 0

#define JWT_DELIMETER_LITERAL ",}"

static int is_delimiter(char ch)
{
    return strchr(JWT_DELIMETER_LITERAL, ch) != NULL ? SUCCESS : FAIL;
}

char* get_json_field_value(
    char* json_str,
    const char* field_name)
{
    char* result = NULL;
    if (field_name == NULL || strlen(field_name) == 0)
    {
        goto done;
    }

    char* needle = malloc(strlen(field_name) + 4);
    if (needle == NULL)
    {
        goto done;
    }
    sprintf(needle, "\"%s\":", field_name);
    needle[strlen(field_name) + 3] = '\0';
    char* payload = strstr(json_str, needle);

    if (payload == NULL)
    {
        goto done;
    }
    payload += strlen(needle);
    // left trim the payload
    for (; *payload != '\0' && *payload == ' '; payload++)
        ;
    if (*payload == '\0')
    {
        printf(FAILMSG("\nMalformed JSON string:\n%s\n"), json_str);
        goto done;
    }
    char start_ch = payload[0], end_ch = '\0';
    switch (start_ch)
    {
    case '\"':
        end_ch = '\"';
        break;
    case '{':
        end_ch = '}';
    default:
        // for payload w/o enclosing symbols, just set the start, end to empty
        start_ch = '\0';
    }
    char* start_pos = NULL;
    int value_len = 0;
    if (start_ch == '\0')
    {  // handle situation w/o encloser
        start_pos = payload;
        while (is_delimiter(*payload) != SUCCESS && *payload != '\0')
        {
            payload++;
        }
        if (is_delimiter(*payload) != SUCCESS)
        {
            printf(FAILMSG("\nMalformed JSON string:\n%s\n"), json_str);
            goto done;
        }
        value_len = payload - start_pos;
        result = malloc((value_len + 1) * sizeof(char));
        if (result == NULL)
        {
            goto done;
        }
        result[value_len] = '\0';
        // Remove/trim the trailing ' ' spaces from the string end if exists
        while (*result && result[value_len - 1] == ' ')
        {
            value_len--;
            result[value_len] = '\0';
        }
    }
    else
    {
        payload++;  // move to char after start_character, aka actual payload
        start_pos = payload;
        while (*payload != end_ch && *payload != '\0')
        {
            payload++;
        }
        if (*payload == '\0')
        {
            goto done;
        }
        value_len = payload - start_pos;
        result = malloc((value_len + 1) * sizeof(char));
        if (result == NULL)
        {
            goto done;
        }
        result[value_len] = '\0';
    }

    memcpy(result, start_pos, value_len);

done:
    if (needle != NULL)
        free(needle);
    return result;
}

int split_JWT_token(
    char* jwt_string,
    char** jwt_header,
    char** jwt_payload,
    char** jwt_signature)
{
    int ret = FAIL;
    // check the if the JWT string is empty
    if (jwt_string == NULL || jwt_string[0] == '\0')
    {
        goto done;
    }
    // jwt_string + 1 is used to skip the opening "\""
    char *start_ptr = jwt_string + 1, *end_ptr = strchr(jwt_string, '.');
    if (end_ptr == NULL || end_ptr <= start_ptr)
    {
        printf(FAILMSG("\nJWT string with malformed header:\n%s\n"), jwt_string);
        goto done;
    }
    size_t segment_len = end_ptr - start_ptr;
    if (jwt_header != NULL)
    {
        *jwt_header = calloc(segment_len + 1, sizeof(char));
        if (*jwt_header == NULL)
        {
            goto done;
        }
        memcpy(*jwt_header, start_ptr, segment_len);
    }
    start_ptr = end_ptr + 1, end_ptr = strchr(end_ptr + 1, '.');
    if (end_ptr == NULL || end_ptr <= start_ptr)
    {
        printf(FAILMSG("\nJWT string with malformed payload:\n%s\n"), jwt_string);
        goto done;
    }
    segment_len = end_ptr - start_ptr;
    if (jwt_payload != NULL)
    {
        *jwt_payload = calloc(segment_len + 1, sizeof(char));
        if (*jwt_payload == NULL)
        {
            goto done;
        }
        memcpy(*jwt_payload, start_ptr, segment_len);
    }
    start_ptr = end_ptr + 1, end_ptr = strchr(end_ptr + 1, '\"');
    if (end_ptr == NULL)
    {
        goto done;
    }
    segment_len = end_ptr - start_ptr;
    if (jwt_signature != NULL)
    {
        *jwt_signature = calloc(segment_len + 1, sizeof(char));
        if (*jwt_signature == NULL)
        {
            goto done;
        }
        memcpy(*jwt_signature, start_ptr, segment_len);
    }

    ret = SUCCESS;
done:
    return ret;
}
