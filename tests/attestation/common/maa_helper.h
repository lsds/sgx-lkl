#ifndef COMMON_MAA_H
#define COMMON_MAA_H

#ifdef __cplusplus
extern "C"
{
#endif
    int authenticate_and_get_maa_token(
        const char* app_id,
        const char* client_id,
        const char* client_secret,
        const char* report_base64url,
        const char* enclave_private_data_base64url,
        char** maa_token);

#ifdef __cplusplus
}
#endif

#endif  // COMMON_MAA_H
