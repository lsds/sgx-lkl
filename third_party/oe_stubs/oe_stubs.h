#ifndef _OE_STUBS_
#define _OE_STUBS_

#include <stdlib.h>
#include <locale.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/pk.h>

extern int mbedtls_x509_crt_parse_file( mbedtls_x509_crt *chain, const char *path );

extern int mbedtls_x509_crt_parse_path( mbedtls_x509_crt *chain, const char *path );

extern int mbedtls_x509_crl_parse_file( mbedtls_x509_crl *chain, const char *path );

extern int mbedtls_pk_parse_keyfile( mbedtls_pk_context *ctx, const char *path, const char *password );


extern long long int strtoll_l(const char* nptr, char** endptr, int base, locale_t loc);

extern unsigned long long strtoull_l(
    const char* nptr,
    char** endptr,
    int base,
    locale_t loc);

#endif
