#include <stdlib.h>
#include <locale.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/pk.h>

/*
These functions are disabled in OE's mbedTLS, but curl refers to them. We do not want
to use them in an enclave, so we can just report an unavailable feature here.
*/

int mbedtls_x509_crt_parse_file( mbedtls_x509_crt *chain, const char *path )
{
  return MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
}

int mbedtls_x509_crt_parse_path( mbedtls_x509_crt *chain, const char *path )
{
  return MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
}

int mbedtls_x509_crl_parse_file( mbedtls_x509_crl *chain, const char *path )
{
  return MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
}

int mbedtls_pk_parse_keyfile( mbedtls_pk_context *ctx, const char *path, const char *password )
{
  return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}


/*
OE's libcxx expects strtoll_l.
*/

long long int strtoll_l(const char* nptr, char** endptr, int base, locale_t loc)
{
    (void)(loc);
    return strtoll(nptr, endptr, base);
}

unsigned long long strtoull_l(
    const char* nptr,
    char** endptr,
    int base,
    locale_t loc)
{
    (void)(loc);
    return strtoull(nptr, endptr, base);
}