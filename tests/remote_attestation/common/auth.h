#ifndef COMMON_AUTH_H
#define COMMON_AUTH_H

#ifdef __cplusplus
extern "C"
{
#endif

    int get_authentication_token(
        const char* app_id,
        const char* client_id,
        const char* client_secret,
        const char* app_url,
        char** authentication_token);

#ifdef __cplusplus
}
#endif

#endif  // COMMON_AUTH_H
