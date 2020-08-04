#ifndef OE_DEFS_H
#define OE_DEFS_H

#include "../public/bits/defs.h"
#include "../public/bits/report.h"
#include "../public/bits/result.h"

#define OE_PEM_MAX_BYTES (16 * 1024)

#define OE_TRACE_ERROR printf

#define OE_RAISE(RESULT, ...)                             \
    do                                                    \
    {                                                     \
        result = (RESULT);                                \
        if (result != OE_OK)                              \
        {                                                 \
            printf("Error: %d\n", result);                \
        }                                                 \
        goto done;                                        \
    } while (0)

#define OE_RAISE_MSG OE_RAISE
#define OE_RAISE_NO_TRACE OE_RAISE

// This macro checks whether the expression argument evaluates to OE_OK. If not,
// call OE_RAISE
#define OE_CHECK(EXPRESSION)                 \
    do                                       \
    {                                        \
        oe_result_t _result_ = (EXPRESSION); \
        if (_result_ != OE_OK)               \
            OE_RAISE(_result_);              \
    } while (0)

#define OE_CHECK_MSG(EXPRESSION, fmt, ...)              \
    do                                                  \
    {                                                   \
        oe_result_t _result_ = (EXPRESSION);            \
        if (_result_ != OE_OK)                          \
            OE_RAISE_MSG(_result_, fmt, ##__VA_ARGS__); \
    } while (0)

typedef struct _oe_oid_string
{
    // Strictly speaking there is no limit on the length of an OID but we chose
    // 128 (the maximum OID length in the SNMP specification). Also, this value
    // is hardcoded to 64 in many implementations.
    char buf[128];
} oe_oid_string_t;


typedef struct _oe_cert
{
    /* Internal private implementation */
    uint64_t impl[4];
} oe_cert_t;

typedef struct _oe_cert_chain
{
    /* Internal private implementation */
    uint64_t impl[4];
} oe_cert_chain_t;

typedef struct _oe_crl
{
    /* Internal private implementation */
    uint64_t impl[4];
} oe_crl_t;

typedef struct _crl
{
    uint64_t magic;
    mbedtls_x509_crl* crl;
} crl_t;

/* Opaque representation of a public RSA key */
typedef struct _oe_rsa_public_key
{
    /* Internal implementation */
    uint64_t impl[4];
} oe_rsa_public_key_t;

/* Opaque representation of a public EC key */
typedef struct _oe_ec_public_key
{
    /* Internal implementation */
    uint64_t impl[4];
} oe_ec_public_key_t;

/* Supported CURVE types */
typedef enum oe_ec_type_t
{
    OE_EC_TYPE_SECP256R1,
    __OE_EC_TYPE_MAX = OE_ENUM_MAX,
} oe_ec_type_t;

typedef struct _oe_public_key
{
    uint64_t magic;
    mbedtls_pk_context pk;
} oe_public_key_t;

typedef oe_result_t (*oe_copy_key)(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copy_private_fields);

static uint64_t _PUBLIC_KEY_MAGIC = 0x713600af058c447a;


#define KEY_BUFF_SIZE 2048
#define X509_OID_FOR_QUOTE_STRING "1.2.840.113556.10.1.1"

static const char* oid_oe_report = X509_OID_FOR_QUOTE_STRING;


oe_result_t oe_cert_read_der(
    oe_cert_t* cert,
    const void* der_data,
    size_t der_size);

oe_result_t oe_cert_find_extension(
    const oe_cert_t* cert,
    const char* oid,
    uint8_t* data,
    size_t* size);

oe_result_t oe_cert_verify(
    oe_cert_t* cert,
    oe_cert_chain_t* chain,
    const oe_crl_t* const* crls,
    size_t num_crls);

oe_result_t oe_cert_write_public_key_pem(
    const oe_cert_t* cert,
    uint8_t* pem_data,
    size_t* pem_size);

oe_result_t oe_cert_free(oe_cert_t* cert);

oe_result_t oe_cert_get_rsa_public_key(
    const oe_cert_t* cert,
    oe_rsa_public_key_t* public_key);

oe_result_t oe_cert_get_ec_public_key(
    const oe_cert_t* cert,
    oe_ec_public_key_t* public_key);

#endif
