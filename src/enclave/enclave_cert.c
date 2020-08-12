#include "enclave/enclave_cert.h"
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <openenclave/enclave.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/eeid_plugin.h>
#include "openenclave/corelibc/oemalloc.h"
#include "openenclave/corelibc/oestring.h"

oe_result_t oe_sgx_eeid_attester_initialize(void);

static oe_result_t _generate_key_pair(
    uint8_t** public_key_out,
    size_t* public_key_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t ret;
    oe_asymmetric_key_params_t params;
    char user_data[] = "__USER_DATA__";
    size_t user_data_size = sizeof(user_data) - 1;
    uint8_t* public_key = NULL;
    size_t public_key_size = 0;
    uint8_t* private_key = NULL;
    size_t private_key_size = 0;

    *public_key_out = NULL;
    *public_key_size_out = 0;
    *private_key_out = NULL;
    *private_key_size_out = 0;

    memset(&params, 0, sizeof(params));
    params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
    params.format = OE_ASYMMETRIC_KEY_PEM;
    params.user_data = user_data;
    params.user_data_size = user_data_size;

    if ((ret = oe_get_public_key_by_policy(
             OE_SEAL_POLICY_UNIQUE,
             &params,
             &public_key,
             &public_key_size,
             NULL,
             NULL)) != OE_OK)
    {
        result = ret;
        goto done;
    }

    if ((ret = oe_get_private_key_by_policy(
             OE_SEAL_POLICY_UNIQUE,
             &params,
             &private_key,
             &private_key_size,
             NULL,
             NULL)) != OE_OK)
    {
        result = ret;
        goto done;
    }

    *private_key_out = private_key;
    *private_key_size_out = private_key_size;
    private_key = NULL;

    *public_key_out = public_key;
    *public_key_size_out = public_key_size;
    public_key = NULL;

    result = OE_OK;

done:

    if (private_key)
        oe_free(private_key);

    if (public_key)
        oe_free(public_key);

    return result;
}

static oe_result_t _generate_cert_and_private_key(
    const char* common_name,
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t ret;
    uint8_t* cert = NULL;
    size_t cert_size;
    uint8_t* private_key = NULL;
    size_t private_key_size;
    uint8_t* public_key = NULL;
    size_t public_key_size;
    const oe_uuid_t format = {OE_FORMAT_UUID_SGX_EEID_ECDSA_P256};

    *cert_out = NULL;
    *cert_size_out = 0;
    *private_key_out = NULL;
    *private_key_size_out = 0;

    if ((ret = _generate_key_pair(
             &public_key, &public_key_size, &private_key, &private_key_size)) !=
        OE_OK)
    {
        result = ret;
        goto done;
    }

    // Initialize built-in OE attesters and the eeid attester.
    oe_attester_initialize();
    oe_sgx_eeid_attester_initialize();

    if ((ret = oe_get_attestation_certificate_with_evidence(
             &format,
             (unsigned char*)common_name,
             private_key,
             private_key_size,
             public_key,
             public_key_size,
             &cert,
             &cert_size)) != OE_OK)
    {
        result = ret;
        goto done;
    }

    *private_key_out = private_key;
    *private_key_size_out = private_key_size;
    private_key = NULL;

    *cert_out = cert;
    *cert_size_out = cert_size;
    cert = NULL;

    result = OE_OK;

done:

    if (private_key)
        oe_free_key(private_key, private_key_size, NULL, 0);

    if (public_key)
        oe_free_key(public_key, public_key_size, NULL, 0);

    if (cert)
        oe_free_attestation_certificate(cert);

    return result;
}

int enclave_generate_tls_credentials(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out)
{
    int ret = -1;
    uint8_t* cert = NULL;
    size_t cert_size;
    uint8_t* private_key = NULL;
    size_t private_key_size;
    const char* common_name = "CN=Open Enclave SDK,O=OESDK TLS,C=US";

    if (cert_out)
        *cert_out = NULL;

    if (cert_size_out)
        *cert_size_out = 0;

    if (private_key_out)
        *private_key_out = NULL;

    if (private_key_size_out)
        *private_key_size_out = 0;

    if (!cert_out || !cert_size_out || !private_key_out ||
        !private_key_size_out)
    {
        goto done;
    }

    /* Generate the attested certificate and private key */
    if (_generate_cert_and_private_key(
            common_name, &cert, &cert_size, &private_key, &private_key_size) !=
        OE_OK)
    {
        goto done;
    }

#if DEBUG
    /* Verify that the certificate can be parsed as DER */
    {
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);

        if (mbedtls_x509_crt_parse_der(&crt, cert, cert_size) != 0)
        {
            mbedtls_x509_crt_free(&crt);
            goto done;
        }

        mbedtls_x509_crt_free(&crt);
    }

    /* Verify that the private key can be parsed as PEM */
    {
        mbedtls_pk_context pk;
        mbedtls_pk_init(&pk);

        if (mbedtls_pk_parse_key(&pk, private_key, private_key_size, NULL, 0) !=
            0)
        {
            mbedtls_pk_free(&pk);
            goto done;
        }

        mbedtls_pk_free(&pk);
    }
#endif

    *cert_out = cert;
    cert = NULL;
    *cert_size_out = cert_size;
    *private_key_out = private_key;
    private_key = NULL;
    *private_key_size_out = private_key_size;

    ret = 0;

done:

    if (cert)
        oe_free_key(cert, cert_size, NULL, 0);

    if (private_key)
        oe_free_key(private_key, private_key_size, NULL, 0);

    if (cert)
        oe_free_attestation_certificate(cert);

    return ret;
}
