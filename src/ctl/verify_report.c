/*
Based on
https://github.com/cloud-security-research/sgx-ra-tls/blob/7d11cddb10d61f32f6eea53c775e4fa25c70146c/openssl-ra-challenger.c.
See copyright below.

Copyright 2017, Intel(R) Corporation (http://www.intel.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "attest_ias.h"
#include "platform_info_blob.h"
#include "sgxlkl_util.h"
#include "verify_report.h"

#define PLATFORM_INFO_BLOB_PREFIX "\"platformInfoBlob\":\""

#define JSON_PREFIX_QUOTE_STATUS "\"isvEnclaveQuoteStatus\":\""
#define JSON_PREFIX_QUOTE_BODY "\"isvEnclaveQuoteBody\":\""

#define STATUS_OK "OK\""
#define STATUS_OUT_OF_DATE "GROUP_OUT_OF_DATE\""
#define STATUS_CONFIG_NEEDED "CONFIGURATION_NEEDED\""

extern unsigned char default_ias_sign_ca_cert_der[];
extern unsigned int default_ias_sign_ca_cert_der_len;

/* EVP_DecodeBlock pads its output with \0 if the output length is not
   a multiple of 3. Check if the base64 string is padded at the end
   and adjust the output length. */
static int EVP_DecodeBlock_wrapper(unsigned char *out,
                                   const unsigned char *in,
                                   int in_len) {
    /* Use a temporary output buffer. We do not want to disturb the
       original output buffer with extraneous \0 bytes. */
    unsigned char buf[in_len];

    int ret = EVP_DecodeBlock(buf, in, in_len);
    assert(ret != -1);
    if (in[in_len-1] == '=' && in[in_len-2] == '=') {
        ret -= 2;
    } else if (in[in_len-1] == '=') {
        ret -= 1;
    }

    memcpy(out, buf, ret);
    return ret;
}

void get_quote_from_report(const uint8_t* report /* in */,
                           const int report_len  /* in */,
                           sgx_quote_t* quote) {
    // Move report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[report_len + 1];
    memcpy(buf, report, report_len);
    buf[report_len] = '\0';

    char* p_begin = strstr(buf, JSON_PREFIX_QUOTE_BODY);
    assert(p_begin != NULL);
    p_begin += strlen(JSON_PREFIX_QUOTE_BODY);
    const char* p_end = strchr(p_begin, '"');
    assert(p_end != NULL);

    const int quote_base64_len = p_end - p_begin;
    uint8_t* quote_bin = malloc(quote_base64_len);
    uint32_t quote_bin_len = quote_base64_len;

    int ret = EVP_DecodeBlock(quote_bin, (unsigned char*) p_begin, quote_base64_len);
    assert(ret != -1);
    quote_bin_len = ret;

    assert(quote_bin_len <= sizeof(sgx_quote_t));
    memset(quote, 0, sizeof(sgx_quote_t));
    memcpy(quote, quote_bin, quote_bin_len);
    free(quote_bin);
}

static int verify_ias_report_signature(attestation_verification_report_t* attn_report) {
    X509* crt = NULL;
    int ret;

    const unsigned char* p = attn_report->ias_sign_cert;
    crt = d2i_X509(NULL,
                   &p,
                   attn_report->ias_sign_cert_len);
    assert(crt != NULL);

    EVP_PKEY* key = X509_get_pubkey(crt);
    assert(key != NULL);

    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    ret = EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL);
    assert(ret == 1);

    ret = EVP_VerifyUpdate(ctx, attn_report->ias_report, attn_report->ias_report_len);
    assert(ret == 1);

    ret = EVP_VerifyFinal(ctx,
                          attn_report->ias_report_signature,
                          attn_report->ias_report_signature_len,
                          key);
    assert(ret == 1);

    EVP_MD_CTX_destroy(ctx);

    return 0;                   /* success */
}

static int verify_ias_certificate_chain(const char *sign_ca_cert_pem_path, attestation_verification_report_t* attn_report) {
    long err;
    FILE *caf;
    const unsigned char* p = attn_report->ias_sign_cert;
    X509* crt = d2i_X509(NULL, &p, attn_report->ias_sign_cert_len);
    if (!crt) {
        while (err = ERR_get_error())
            sgxlkl_err("IAS Sign Cert d2i_X509 error: %s\n", ERR_error_string(err, NULL));
        return 1;
    }

    X509* cacrt;
    if (sign_ca_cert_pem_path) {
        if ((caf = fopen(sign_ca_cert_pem_path, "r")) == NULL) {
            sgxlkl_err("Failed to open IAS signing CA certificate with path %s: %s\n", sign_ca_cert_pem_path, strerror(errno));
            return 1;
        }
        cacrt = PEM_read_X509(caf, NULL, NULL, NULL);
        if (!cacrt) {
            while (err = ERR_get_error())
                sgxlkl_err("Failed to read IAS signing CA certificate with path %s: %s\n", sign_ca_cert_pem_path, ERR_error_string(err, NULL));
            return 1;
        }

        fclose(caf);
    } else { /* Use default IAS signing CA cert */
        sgxlkl_info("No IAS signing CA certificate provided, using default.\n");
        p = default_ias_sign_ca_cert_der;
        cacrt = d2i_X509(NULL, &p, default_ias_sign_ca_cert_der_len);
        if (!cacrt) {
            while (err = ERR_get_error())
                sgxlkl_err("IAS Sign CA Cert d2i_X509 error: %s\n", ERR_error_string(err, NULL));
            return 1;
        }
    }


    X509_STORE* s = X509_STORE_new();
    X509_STORE_add_cert(s, cacrt);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, s, crt, NULL);

    int rc = X509_verify_cert(ctx);
    if (rc != 1) {
        err = X509_STORE_CTX_get_error(ctx);
        sgxlkl_warn("Failed to verify certificate chain: %s\n", X509_verify_cert_error_string(err));
        return 1;
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(s);

    return rc != 1;                   /* 1 .. fail, 0 .. success */
}

/**
 * Check if isvEnclaveQuoteStatus is "OK"
 * (cf. https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf,
 * pg. 24).
 *
 * @return 0 if verified successfully, 1 otherwise.
 */
static int verify_enclave_quote_status(int strict,
                                       const char* ias_report,
                                       int ias_report_len) {
    // Move ias_report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[ias_report_len + 1];
    memcpy(buf, ias_report, ias_report_len);
    buf[ias_report_len] = '\0';

    char* p_begin = strstr(buf, JSON_PREFIX_QUOTE_STATUS);
    assert(p_begin != NULL);
    p_begin += strlen(JSON_PREFIX_QUOTE_STATUS);

    if (0 == strncmp(p_begin, STATUS_OK, strlen(STATUS_OK))) {
         sgxlkl_info("Quote status: OK\n");
         return 0;
    } else if (0 == strncmp(p_begin, STATUS_OUT_OF_DATE, strlen(STATUS_OUT_OF_DATE))) {
        sgxlkl_warn("Quote status: GROUP_OUT_OF_DATE (Platform software/firmare is out of date)\n");
        return strict ? 1 : 0;
    } else if (0 == strncmp(p_begin, STATUS_CONFIG_NEEDED, strlen(STATUS_CONFIG_NEEDED))) {
        int ret = strict ? 1 : 0;
        sgxlkl_warn("Quote status: CONFIGURATION_NEEDED (Target systems requires reconfiguration)\n");

        size_t blob_key_len = strlen(PLATFORM_INFO_BLOB_PREFIX);
        char *blob = strstr(buf, PLATFORM_INFO_BLOB_PREFIX);
        if (!blob) {
            sgxlkl_err("Could not parse platform info blob in IAS response.\n");
            return ret;
        }
        blob += blob_key_len;
        size_t blob_length = strchr(blob, '"') - blob;
        if (blob_length < 210) {
            sgxlkl_err("Incomplete platform blob, length: %lu.\n", blob_length);
            return ret;
        }
        char blob_str[blob_length + 1];
        memcpy(blob_str, blob, blob_length);
        blob_str[blob_length] = '\0';
        char *decoded_blob;
        ssize_t decoded_len = hex_to_bytes(blob_str, &decoded_blob);
        // +4 for TSV header
        if (decoded_len != sizeof(struct platform_info_blob) + 4) {
            sgxlkl_err("Invalid platform blob, expected length: %lu, actual length: %lu, sizeof(struct platform_info_blob): %lu.\n",
                sizeof(struct platform_info_blob) + 4,
                decoded_len,
                sizeof(struct platform_info_blob));
            return ret;
        }

        struct platform_info_blob *pi = (struct platform_info_blob *) (decoded_blob + 4);

        sgxlkl_warn("Platform Info:\n");
        sgxlkl_warn(" EPID group flags: 0x%x\n", pi->sgx_epid_group_flags);
        sgxlkl_warn(" TCB evaluation flags: 0x%x%x\n", pi->sgx_tcb_evaluation_flags[0], pi->sgx_tcb_evaluation_flags[1]);
        sgxlkl_warn(" PSE evaluation flags: 0x%x%x\n", pi->pse_evaluation_flags[0], pi->pse_evaluation_flags[1]);

        free(decoded_blob);
        return ret;
    } else {
        // TODO Print actual enclave quote status here.
        sgxlkl_warn("Quote status: Unknown!\n");
    }

    return 1;
}

int verify_quote(sgx_quote_t *quote, const char *mrenclave_hex, const char *mrsigner_hex) {
    int ret = 0;
    char *mrenclave = NULL, *mrsigner = NULL;

    sgx_report_body_t* body = &quote->report_body;
    sgxlkl_info("Quote measurements:\n");
    sgxlkl_info(" MRENCLAVE: ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) fprintf(stderr, "%02x", body->mr_enclave.m[i]);
    fprintf(stderr, "\n");

    sgxlkl_info(" MRSIGNER:  ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) fprintf(stderr, "%02x", body->mr_signer.m[i]);
    fprintf(stderr, "\n");

    if (!mrenclave_hex) {
        sgxlkl_info("No expected MRENCLAVE specified. Skipping verification.\n");
    } else {
        size_t mrenclave_len = hex_to_bytes(mrenclave_hex, &mrenclave);
        if (mrenclave_len != SGX_HASH_SIZE || memcmp(body->mr_enclave.m, mrenclave, SGX_HASH_SIZE)) {
            sgxlkl_warn("MRENCLAVE mismatch. Verification failed!\n");
            ret = 1;
        }
    }

    if (!mrsigner_hex) {
        sgxlkl_info("No expected MRSIGNER specified. Skipping verification.\n");
    } else {
        size_t mrsigner_len = hex_to_bytes(mrsigner_hex, &mrsigner);
        if (mrsigner_len != SGX_HASH_SIZE || memcmp(body->mr_signer.m, mrsigner, SGX_HASH_SIZE)) {
            sgxlkl_warn("MRSIGNER mismatch. Verification failed!\n");
            ret = 1;
        }
    }

    free(mrenclave);
    free(mrsigner);

    return ret;
}

/**
 * @return 0 if verified successfully, 1 otherwise.
 */
int verify_report(int strict, const char *ias_sign_ca_cert_pem, attestation_verification_report_t *attn_report,
                  const char *mrenclave_hex, const char *mrsigner_hex, uint64_t nonce) {
    int ret = 0, err = 0;

    if (err = verify_ias_certificate_chain(ias_sign_ca_cert_pem, attn_report)) {
        ret = 1;
        if (strict)
            return err;
    }

    if (err = verify_ias_report_signature(attn_report)) {
        ret = 1;
        if (strict)
            return err;
    }

    if (err = verify_enclave_quote_status(strict,
                                      (const char*) attn_report->ias_report,
                                      attn_report->ias_report_len)) {
        sgxlkl_warn("Quote status verification failed.\n");
        if (strict)
            return err;
    }

    sgx_quote_t quote = {0, };
    get_quote_from_report(attn_report->ias_report,
                          attn_report->ias_report_len,
                          &quote);
    if (err = verify_quote(&quote, mrenclave_hex, mrsigner_hex))
        ret = 1;

    return ret;
}

