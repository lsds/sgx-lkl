#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>
#include <stdio.h>
#include <string.h>

#include "../../common/maa.h"
#include "../../common/json_utils.h"
#include "../../common/log_utils.h"
#include "../../common/settings.h"
#include "../../common/transport_utils.h"
#include "../oe_public/host_verify.h"
#include "oe_defs.h"

int _maa_verify_report(
    uint8_t* report,
    size_t report_size,
    uint8_t* pub_key_buf,
    size_t pub_key_buf_size,
    oe_identity_verify_callback_t enclave_identity_callback)
{
    char* app_id = NULL;
    char* client_id = NULL;
    char* client_secret = NULL;
    size_t buf_size = 0;
    char* report_base64 = NULL;
    size_t report_base64_size = 0;
    char* report_data_base64 = NULL;
    size_t report_data_base64_size = 0;
    int ret = 0;
    char* maa_token = NULL;
    char* maa_jwt_payload = NULL;
    char *sgx_mrenclave = NULL, *sgx_mrsigner = NULL, *product_id = NULL;
    oe_identity_t* identity = NULL;

    ret = encode_base64url(report, report_size, &report_base64, &report_base64_size);
    if (ret != 0)
    {
        printf(FAILMSG("Failed to encode report, error = %d\n"), ret);
        goto done;
    }

    ret = encode_base64url(pub_key_buf, pub_key_buf_size, &report_data_base64, &report_data_base64_size);
    if (ret != 0)
    {
        printf(FAILMSG("Failed to encode public key, error = %d\n"), ret);
        goto done;
    }

    app_id = get_environment_variable("MAA_APP_ID");
    client_id = get_environment_variable("MAA_CLIENT_ID");
    client_secret = get_environment_variable("MAA_CLIENT_SECRET");

    ret = authenticate_and_get_maa_token(
        app_id,
        client_id,
        client_secret,
        report_base64,
        report_data_base64,
        &maa_token);
    if (ret != 0)
    {
        printf(FAILMSG("Failed to encode public key, error = %d\n"), ret);
        goto done;
    }

    printf(SUCCESSMSG("MAA JSON Web Tokens:\n%s\n"), maa_token);
    if (enclave_identity_callback)
    {
        ret = parse_JWT_token(maa_token, NULL, &maa_jwt_payload, NULL);
        if (ret != 0)
        {
            printf(FAILMSG("Failed to parse MAA JWT token."));
            goto done;
        } else {
            printf(SUCCESSMSG("Successfully parsed MAA JWT token:\n"));	
	}

        // populate the OpenEnclave identity for verifier
        identity = malloc(sizeof(oe_identity_t));
        if (identity == NULL)
        {
            goto done;
        }
        // Initialize identity attributes
        identity->attributes = 0;
        identity->id_version = 0;
        identity->security_version = 0;
        product_id = get_json_field_value(maa_jwt_payload, "product-id");

        if (product_id == NULL)
        {
            printf(FAILMSG("\nFailed to extract product id from MAA JWT.\n"));
            goto done;
        }
        if (strlen(product_id) + 1 > OE_PRODUCT_ID_SIZE)  // need to include the end '\0'
        {
            printf(FAILMSG("\nThe product id get from MAA JWT exceeds the maximum OE_PRODUCT_ID_SIZE \n%s\n "), product_id);
            goto done;
        }
	printf(SUCCESSMSG("Successfully extracted product id from MAA JWT.\n"));
        // product id buffer needs to hold product_id and one more char for '\0'
        memset(identity->product_id, '\0', OE_PRODUCT_ID_SIZE);
        strncpy(identity->product_id, product_id, strlen(product_id));
        sgx_mrenclave = get_json_field_value(maa_jwt_payload, "sgx-mrenclave");
        ret = hexstr_to_chararr(identity->unique_id,
                                OE_UNIQUE_ID_SIZE,
                                sgx_mrenclave,
                                strlen(sgx_mrenclave));
        if (ret != 0)
        {
            printf(FAILMSG("Failed to populate OE identity. Incorrect size of sgx_mrenclave"));
            goto done;
        }
        sgx_mrsigner = get_json_field_value(maa_jwt_payload, "sgx-mrsigner");
        ret = hexstr_to_chararr(identity->signer_id,
                                OE_SIGNER_ID_SIZE,
                                sgx_mrsigner,
                                strlen(sgx_mrsigner));
        if (ret != 0)
        {
            printf(FAILMSG("Failed to populate OE identity. Incorrect size of sgx_mrsigner"));
            goto done;
        }
        printf(SUCCESSMSG("Successfuly populated OE identity from MAA JWT\n"));
        ret = enclave_identity_callback(identity, NULL);
    }

done:
    if (maa_token != NULL)
        free(maa_token);
    if (report_base64 != NULL)
        free(report_base64);
    if (report_data_base64 != NULL)
        free(report_data_base64);
    if (maa_jwt_payload != NULL)
        free(maa_jwt_payload);
    if (sgx_mrenclave != NULL)
        free(sgx_mrenclave);
    if (sgx_mrsigner != NULL)
        free(sgx_mrsigner);
    if (identity != NULL)
        free(identity);

    return ret;
}

oe_result_t _oe_verify_attestation_certificate(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_identity_verify_callback_t enclave_identity_callback,
    void* arg)
{
    oe_result_t result = OE_FAILURE;
    oe_cert_t cert = {0};
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* pub_key_buf = NULL;
    size_t pub_key_buf_size = KEY_BUFF_SIZE;
    oe_report_t parsed_report = {0};
    int ret = -1;

    pub_key_buf = (uint8_t*)malloc(KEY_BUFF_SIZE);
    if (!pub_key_buf)
        OE_RAISE(OE_OUT_OF_MEMORY);

    result = oe_cert_read_der(&cert, cert_in_der, cert_in_der_len);
    OE_CHECK_MSG(result, "cert_in_der_len=%d", cert_in_der_len);

    // validate the certificate signature
    result = oe_cert_verify(&cert, NULL, NULL, 0);
    OE_CHECK_MSG(
        result,
        "oe_cert_verify failed with error = %s\n",
        oe_result_str(result));

    // determine the size of the extension
    if (oe_cert_find_extension(
            &cert, (const char*)oid_oe_report, NULL, &report_size) !=
        OE_BUFFER_TOO_SMALL)
        OE_RAISE(OE_FAILURE);

    report = (uint8_t*)malloc(report_size);
    if (!report)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // find the extension
    OE_CHECK(oe_cert_find_extension(
        &cert, (const char*)oid_oe_report, report, &report_size));

    // extract public key from the cert
    memset(pub_key_buf, 0, KEY_BUFF_SIZE);
    result = oe_cert_write_public_key_pem(&cert, pub_key_buf, &pub_key_buf_size);
    OE_CHECK(result);

    ret = _maa_verify_report(report, report_size, pub_key_buf, pub_key_buf_size, enclave_identity_callback);
    if (ret != 0)
    {
        printf("MAA report verification failed, error = %d\n", ret);
        goto done;
    } else {
	printf("MAA report verification succeeded\n");
    }

done:
    free(pub_key_buf);
    oe_cert_free(&cert);
    free(report);
    return result;
}
