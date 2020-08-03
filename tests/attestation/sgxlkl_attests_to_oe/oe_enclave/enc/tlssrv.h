#ifndef _TLSSRV_H
#define _TLSSRV_H

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>

typedef struct _tlssrv_err
{
    char buf[1024];
} tlssrv_err_t;

typedef oe_result_t (*verify_identity_function_t)(
    void* arg,
    const uint8_t* mrenclave,
    size_t mrenclave_size,
    const uint8_t* mrsigner,
    size_t mrsigner_size,
    const uint8_t* isvprodid,
    size_t isvprodid_size,
    uint64_t isvsvn);

typedef struct _tlssrv
{
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;
    mbedtls_ssl_cache_context cache;
    verify_identity_function_t verify_identity;
    void* verify_identity_arg;
} tlssrv_t;

#endif /* _TLSSRV_H */
