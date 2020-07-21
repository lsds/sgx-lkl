#include "transport_utils.h"

#include <mbedtls/base64.h>
#include <mbedtls/error.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#include "json_utils.h"
#include "log_utils.h"

#define FAIL -1
#define SUCCESS 0
#define TRANSPORT_BUFF_SIZE_SMALL 1024
#define TRANSPORT_BUFF_SIZE_LARGE 10240

static void print_mbedtls_error_info(int mbedtls_ret_val)
{
    char buf[TRANSPORT_BUFF_SIZE_LARGE];
    mbedtls_strerror(mbedtls_ret_val, buf, TRANSPORT_BUFF_SIZE_LARGE);
    printf(FAILMSG("\nError info:\n %s\n"), buf);
}

static int base64_encode_decode(
    int (*coding_func)(unsigned char*, size_t, size_t*, const unsigned char*, size_t),
    const uint8_t* in,
    size_t in_len,
    char** out,
    size_t* out_len,
    size_t init_buf_size)
{
    int ret;
    if (in == NULL || out == NULL)
    {
        goto fail;
    }
    // The mbedtls document indicate, for both encode and decode base64 function,
    // setting either the first param to NULL or second param to 0 will populate
    // the actual written bytes to third param.
    ret = coding_func(NULL, 0, out_len, in, in_len);

    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
        print_mbedtls_error_info(ret);
        goto fail;
    }
    *out = malloc(*out_len + 1);
    if (*out == NULL)
    {
        goto fail;
    }
    ret = coding_func((uint8_t*)(*out), *out_len, out_len, in, in_len);
    if (ret != 0)
    {
        print_mbedtls_error_info(ret);
        goto fail;
    }
    (*out)[*out_len] = '\0';

    return SUCCESS;
fail:
    if (out != NULL && *out != NULL)
        free(*out);
    *out = NULL;
    *out_len = 0;
    return FAIL;
}

int decode_base64(
    const uint8_t* in,
    size_t in_len,
    char** out,
    size_t* out_len)
{
    return base64_encode_decode(mbedtls_base64_decode, in, in_len, out, out_len, TRANSPORT_BUFF_SIZE_SMALL);
}

int decode_base64url(
    const uint8_t* in,
    size_t in_len,
    char** out,
    size_t* out_len)
{
    int ret = FAIL;
    uint8_t* in_base64 = malloc(in_len + 3);
    if (in_base64 == NULL)
    {
        goto done;
    }
    // replace '-' with '+', '_' with '/'
    for (int i = 0; i < in_len; i++)
    {
        in_base64[i] = in[i] == '-' ? '+' : in[i] == '_' ? '/' : in[i];
    }

    int padding_len = 0;
    switch (in_len % 4)  // Pad with trailing '='s
    {
    case 0:  // No tail padding
        break;
    case 2:  // tail pad two '='s
        in_base64[in_len] = '=';
        in_base64[in_len + 1] = '=';
        padding_len = 2;
        break;
    case 3:  // tail pad one '='
        in_base64[in_len] = '=';
        padding_len = 1;
        break;
    default:
        printf(FAILMSG("\nTrying to decode illegal base64url string:\n%s\n"), in);
        goto done;
    }
    size_t in_base64_len = in_len + padding_len;
    in_base64[in_base64_len] = '\0';

    ret = base64_encode_decode(mbedtls_base64_decode, in_base64, in_base64_len, out, out_len, TRANSPORT_BUFF_SIZE_SMALL);

done:
    if (in_base64 != NULL)
        free(in_base64);
    return ret;
}

int encode_base64(
    const uint8_t* in,
    size_t in_len,
    char** out,
    size_t* out_len)
{
    return base64_encode_decode(mbedtls_base64_encode, in, in_len, out, out_len, TRANSPORT_BUFF_SIZE_SMALL);
}

int encode_base64url(
    const uint8_t* in,
    size_t in_len,
    char** out,
    size_t* out_len)
{
    int ret = encode_base64(in, in_len, out, out_len);
    if (ret != SUCCESS)
    {
        return FAIL;
    }
    // replace '+' with '-', '/' with '_'
    if (*out && *out_len)
    {
        for (int i = 0; i < in_len; i++)
        {
            (*out)[i] = (*out)[i] == '+' ? '-' : (*out)[i] == '/' ? '_' : (*out)[i];
        }
        // Remove/trim the trailing '=' chars from the string end if exists
        while (*out_len && ((*out)[(*out_len) - 1]) == '=')
        {
            (*out_len)--;
            (*out)[*out_len] = '\0';
        }
    }
    return SUCCESS;
}

int parse_JWT_token(
    char* jwt_string,
    char** jwt_header,
    char** jwt_payload,
    char** jwt_signature)
{
    int ret = split_JWT_token(jwt_string, jwt_header, jwt_payload, jwt_signature);
    if (ret != SUCCESS)
    {
        goto done;
    }
    ret = FAIL;
    if (jwt_header != NULL)
    {
        int len = strlen(*jwt_header);
        char* jwt_header_copy = malloc((len + 1) * sizeof(char));
        if (jwt_header_copy == NULL)
        {
            goto done;
        }
        jwt_header_copy[len] = '\0';
        memcpy(jwt_header_copy, *jwt_header, len);
        free(*jwt_header);
        size_t jwt_header_len;
        ret = decode_base64url((const uint8_t*)jwt_header_copy, len, jwt_header, &jwt_header_len);
        free(jwt_header_copy);
        if (ret != SUCCESS || jwt_header_len == 0)
        {
            goto done;
        }
    }
    if (jwt_payload != NULL)
    {
        int len = strlen(*jwt_payload);
        char* jwt_payload_copy = malloc((len + 1) * sizeof(char));
        if (jwt_payload_copy == NULL)
        {
            goto done;
        }
        jwt_payload_copy[len] = '\0';
        memcpy(jwt_payload_copy, *jwt_payload, len);
        free(*jwt_payload);
        size_t jwt_payload_len;
        ret = decode_base64url((const uint8_t*)jwt_payload_copy, len, jwt_payload, &jwt_payload_len);
        free(jwt_payload_copy);
        if (ret != SUCCESS || jwt_payload_len == 0)
        {
            goto done;
        }
    }
    if (jwt_signature != NULL)
    {
        int len = strlen(*jwt_signature);
        char* jwt_signature_copy = malloc((len + 1) * sizeof(char));
        if (jwt_signature_copy == NULL)
        {
            goto done;
        }
        jwt_signature_copy[len] = '\0';
        memcpy(jwt_signature_copy, *jwt_signature, len);
        free(*jwt_signature);
        size_t jwt_signature_len;
        ret = decode_base64url((const uint8_t*)jwt_signature_copy, len, jwt_signature, &jwt_signature_len);
        free(jwt_signature_copy);
    }

done:
    return ret;
}

int hexstr_to_chararr(uint8_t* dest, size_t dest_len, char* src, size_t src_len)
{
    int ret = FAIL;
    char* segment = NULL;
    int invalid = dest == NULL || src == NULL || dest_len == 0 || src_len == 0 || src_len % dest_len != 0;
    if (invalid)
    {
        goto done;
    }

    size_t segment_len = src_len / dest_len;
    segment = malloc(sizeof(char) * (segment_len + 1));
    if (segment == NULL)
    {
        goto done;
    }
    segment[segment_len] = '\0';
    if (segment == NULL)
    {
        goto done;
    }
    int val = 0;
    for (size_t i = 0; i < dest_len; i++)
    {
        memcpy(segment, src + i * segment_len, 2);
        sscanf(segment, "%x", &val);
        dest[i] = val;
    }

    ret = SUCCESS;
done:
    if (segment != NULL)
        free(segment);
    return ret;
}
