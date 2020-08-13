#ifndef TRANSPORT_UTIL_H
#define TRANSPORT_UTIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    int encode_base64(
        const uint8_t *in,
        size_t in_len,
        char **out,
        size_t *out_len);

    int encode_base64url(
        const uint8_t *in,
        size_t in_len,
        char **out,
        size_t *out_len);

    int decode_base64(
        const uint8_t *in,
        size_t in_len,
        char **out,
        size_t *out_len);

    

    /**
     * @brief given a raw jwt string. split it to it's three components, can decode from base64url 
     * to plain text, populate the three components(header, payload and signature). If any of the 
     * three component is set to NULL, that component will be skipped.
     * 
     * @param jwt_string The JWT string need to be parsed.
     * @param jwt_header The pointer being used to store the header result. It can be set to 
     * NULL to skip the header result
     * @return will return a SUCCESS/FAIL value predefined in the transport_util
     * @param jwt_payload The pointer being used to store the payload result. It can be set to 
     * NULL to skip the payload result
     * @return will return a SUCCESS/FAIL value predefined in the transport_util
     * @param jwt_signature The pointer being used to store the signature result. It can be set to 
     * NULL to skip the signature result
     * @return will return a SUCCESS/FAIL value predefined in the transport_util
     */
    int parse_JWT_token(
        char *jwt_string,
        char **jwt_header,
        char **jwt_payload,
        char **jwt_signature);

    /**
     * @brief given a raw plain hexstring, parse and convert it to a char array with actual value.
     * 
     * @return will return a SUCCESS/FAIL value predefined in the transport_util
     */
    int hexstr_to_chararr(uint8_t *dest, size_t dest_len, char *src, size_t src_len);

#ifdef __cplusplus
}
#endif

#endif  // TRANSPORT_UTIL_H
