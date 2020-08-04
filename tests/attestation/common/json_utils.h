#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Extract a JSON field value. The field must be in the format 
     * "field_name":<start_encloser>payload_value<end_encloser>
     * 
     * @param json_str The json packet need being parsed.
     * @param field_name The field name will be used to find in the JSON string.
     * @return char* the "payload_value" (without the encloser like '{}' or '""') of the 
     * field_name from the JSON string. If something goes wrong, will return NULL value.
     */
    char *get_json_field_value(
        char *json_str,
        const char *field_name);

    /**
     * @brief JWT (JSON Web Token) is a base64url format string. It has three components:
     * header, payload, signature. This function is used to split a JWT string into it's 
     * three components. more details can be found here: https://jwt.io/introduction/
     * In the project context, the entire JWT payload is always enclosed by double 
     * quotes, looks like the format: "the.JWT.payload"
     * 
     * @param jwt_string The JWT string need to be split.
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
    int split_JWT_token(
        char *jwt_string,
        char **jwt_header,
        char **jwt_payload,
        char **jwt_signature);

#ifdef __cplusplus
}
#endif

#endif  // JSON_UTILS_H
