/*
Based on
https://github.com/cloud-security-research/sgx-ra-tls/blob/ce24b655bb1c1351a25d3bb41a85902b29deb278/ias-ra.c.
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
#define _GNU_SOURCE // for memmem()

#include <assert.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_report.h>

#include "attest.h"
#include "attest_ias.h"
#include "platform_info_blob.h"
#include "sgxlkl_util.h"

#define HTTP_STATUS_OK 200
#define HTTP_STATUS_BAD_REQUEST 400
#define BAD_REQUEST_INFO " ('400 Bad Request' indicates that the quote is invalid. Please ensure that the correct SPID and quote type is provided to both sgx-lkl-run and sgx-lkl-ctl)"

#define QUOTE_STATUS_PREFIX "\"isvEnclaveQuoteStatus\":\""
#define PLATFORM_INFO_BLOB_PREFIX "\"platformInfoBlob\":\""

struct buffer_and_size {
    char* data;
    size_t len;
};

size_t accumulate_function(void *ptr, size_t size, size_t nmemb, void *userdata) {
    struct buffer_and_size* s = (struct buffer_and_size*) userdata;
    s->data = (char*) realloc(s->data, s->len + size * nmemb);
    assert(s->data != NULL);
    memcpy(s->data + s->len, ptr, size * nmemb);
    s->len += size * nmemb;

    return size * nmemb;
}

static const char pem_marker_begin[] = "-----BEGIN CERTIFICATE-----";
static const char pem_marker_end[] = "-----END CERTIFICATE-----";

/* Takes a PEM as input. Strips the PEM header/footer and removes
   newlines (\n). Result is a base64-encoded DER. */
static
void pem_to_base64_der(
    const char* pem,
    uint32_t pem_len,
    char* der,
    uint32_t* der_len,
    uint32_t der_max_len
)
{
    assert(strncmp((char*) pem, pem_marker_begin, strlen(pem_marker_begin)) == 0);
    assert(strncmp((char*) pem + pem_len - strlen(pem_marker_end),
                   pem_marker_end, strlen(pem_marker_end)) == 0);

    uint32_t out_len = 0;
    const char* p = pem + strlen(pem_marker_begin);
    for (uint32_t i = 0;
         i < pem_len - strlen(pem_marker_begin) - strlen(pem_marker_end);
         ++i) {
        if (p[i] == '\n') continue;
        assert(out_len <= der_max_len);
        der[out_len] = p[i];
        out_len++;
    }
    *der_len = out_len;
}

static void base64_encode_internal
(
    uint8_t *in,
    uint32_t in_len,
    uint8_t* out,
    uint32_t* out_len /* in/out */
)
{
    // + 1 to account for the terminating \0.
    assert(*out_len >= (in_len + 3 - 1) / 3 * 4 + 1);
    bzero(out, *out_len);

//    size_t out_l = (size_t) *out_len;
//    sgxlkl_base64_encode((unsigned char *)in, (size_t)in_len, (unsigned char *)out, &out_l);
//    *out_len = (uint32_t)out_l;

        int ret = EVP_EncodeBlock(out, in, in_len);
        // + 1 since EVP_EncodeBlock() returns length excluding the terminating \0.
        assert((size_t) ret + 1 <= *out_len);
        *out_len = ret + 1;
}

/* EVP_DecodeBlock pads its output with \0 if the output length is not
   a multiple of 3. Check if the base64 string is padded at the end
   and adjust the output length. */
static int base64_decode_internal
(
    unsigned char *out,
    const unsigned char *in,
    int in_len
)
{
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

static
void extract_certificates_from_response_header
(
    CURL* curl,
    const char* header,
    size_t header_len,
    attestation_verification_report_t* attn_report
)
{
    // Locate x-iasreport-signature HTTP header field in the response.
    const char response_header_name[] = "X-IASReport-Signing-Certificate: ";
    char *field_begin = memmem(header,
                               header_len,
                               response_header_name,
                               strlen(response_header_name));
    assert(field_begin != NULL);
    field_begin += strlen(response_header_name);
    const char http_line_break[] = "\r\n";
    char *field_end = memmem(field_begin,
                             header_len - (field_begin - header),
                             http_line_break,
                             strlen(http_line_break));
    size_t field_len = field_end - field_begin;

    // Remove urlencoding from x-iasreport-signing-certificate field.
    int unescaped_len = 0;
    char* unescaped = curl_easy_unescape(curl,
                                         field_begin,
                                         field_len,
                                         &unescaped_len);

    char* cert_begin = memmem(unescaped,
                              unescaped_len,
                              pem_marker_begin,
                              strlen(pem_marker_begin));
    assert(cert_begin != NULL);
    char* cert_end = memmem(unescaped, unescaped_len,
                            pem_marker_end, strlen(pem_marker_end));
    assert(cert_end != NULL);
    uint32_t cert_len = cert_end - cert_begin + strlen(pem_marker_end);

    /* This is an overapproximation: after converting from PEM to
       base64-encoded DER the actual size will be less than
       cert_len. */
    assert(cert_len <= sizeof(attn_report->ias_sign_cert));
    pem_to_base64_der(cert_begin, cert_len,
                      (char*) attn_report->ias_sign_cert,
                      &attn_report->ias_sign_cert_len,
                      sizeof(attn_report->ias_sign_cert));

    cert_begin = memmem(cert_end,
                        unescaped_len - (cert_end - unescaped),
                        pem_marker_begin,
                        strlen(pem_marker_begin));
    assert(cert_begin != NULL);
    cert_end = memmem(cert_begin,
                     unescaped_len - (cert_begin - unescaped),
                     pem_marker_end,
                     strlen(pem_marker_end));
    assert(cert_end != NULL);
    cert_len = cert_end - cert_begin + strlen(pem_marker_end);

    assert(cert_len <= sizeof(attn_report->ias_sign_ca_cert));
    pem_to_base64_der(cert_begin, cert_len,
                      (char*) attn_report->ias_sign_ca_cert,
                      &attn_report->ias_sign_ca_cert_len,
                      sizeof(attn_report->ias_sign_ca_cert));


    attn_report->ias_sign_ca_cert_len = base64_decode_internal(attn_report->ias_sign_ca_cert,
                                                               attn_report->ias_sign_ca_cert,
                                                               attn_report->ias_sign_ca_cert_len);
    assert(attn_report->ias_sign_ca_cert_len > 0);
    attn_report->ias_sign_cert_len = base64_decode_internal(attn_report->ias_sign_cert,
                                                            attn_report->ias_sign_cert,
                                                            attn_report->ias_sign_cert_len);
    assert(attn_report->ias_sign_cert_len > 0);

    curl_free(unescaped);
    unescaped = NULL;
}

/* Receive report signature from response header. */
static void parse_response_header
(
    const char* header,
    size_t header_len,
    unsigned char* signature,
    const size_t signature_max_size,
    uint32_t* signature_size,
    int verbose
)
{
    const char sig_tag[] = "X-IASReport-Signature: ";
    char* sig_begin = memmem((const char*) header,
                             header_len,
                             sig_tag,
                             strlen(sig_tag));
    assert(sig_begin != NULL);
    sig_begin += strlen(sig_tag);
    char* sig_end = memmem(sig_begin,
                           header_len - (sig_begin - header),
                           "\r\n",
                           strlen("\r\n"));
    assert(sig_end);

    assert((size_t) (sig_end - sig_begin) <= signature_max_size);
    memcpy(signature, sig_begin, sig_end - sig_begin);
    *signature_size = sig_end - sig_begin;

    *signature_size = base64_decode_internal(signature, signature, *signature_size);
    assert(*signature_size > 0);

    if (verbose) {
        const char advisory_url_tag[] = "advisory-url: ";
        char* advisory_url_begin = memmem((const char*) header,
                                          header_len,
                                          advisory_url_tag,
                                          strlen(advisory_url_tag));
        if (!advisory_url_begin) return;
        advisory_url_begin += strlen(advisory_url_tag);
        char* advisory_url_end = memmem(advisory_url_begin,
                                        header_len - (advisory_url_begin - header),
                                        "\r\n",
                                        strlen("\r\n"));
        if (!advisory_url_end) return;

        const char advisory_ids_tag[] = "advisory-ids: ";
        char* advisory_ids_begin = memmem((const char*) header,
                                          header_len,
                                          advisory_ids_tag,
                                          strlen(advisory_ids_tag));
        if (!advisory_ids_begin) return;
        advisory_ids_begin += strlen(advisory_ids_tag);
        char* advisory_ids_end = memmem(advisory_ids_begin,
                                        header_len - (advisory_ids_begin - header),
                                        "\r\n",
                                        strlen("\r\n"));
        if (!advisory_ids_end) return;

        sgxlkl_info(" One or more advisories apply to the attested platform. Refer to %.*s for more information:\n",
                    advisory_url_end - advisory_url_begin, advisory_url_begin);
        sgxlkl_info("  %.*s\n",
                    advisory_ids_end - advisory_ids_begin, advisory_ids_begin);
    }
}

static void parse_response_body(const char* data, size_t len) {
    size_t status_key_len = strlen(QUOTE_STATUS_PREFIX);
    char *status = memmem(data, len, QUOTE_STATUS_PREFIX, status_key_len);
    if (!status) {
        sgxlkl_warn("Could not parse quote status in IAS response.\n");
        return;
    }
    status += status_key_len;
    // TODO This is not safe! data might not be null-terminated
    size_t status_length = strchr(status, '"') - status;
    if (!status_length) {
        sgxlkl_warn("Incomplete quote status.\n");
        return;
    }
    sgxlkl_info("Intel Attestation Service Response:\n");
    sgxlkl_info(" Quote status: %.*s\n", status_length, status);

    size_t blob_key_len = strlen(PLATFORM_INFO_BLOB_PREFIX);
    char *blob = memmem(data, len, PLATFORM_INFO_BLOB_PREFIX, blob_key_len);
    if (!blob) {
        sgxlkl_warn("Could not parse platform info blob in IAS response.\n");
        return;
    }
    blob += blob_key_len;
    size_t blob_length = strchr(blob, '"') - blob;
    if (blob_length < 210) {
        sgxlkl_warn("Incomplete platform blob, length: %lu.\n", blob_length);
        return;
    }
    char blob_str[blob_length + 1];
    memcpy(blob_str, blob, blob_length);
    blob_str[blob_length] = '\0';
    char *decoded_blob;
    ssize_t decoded_len = hex_to_bytes(blob_str, &decoded_blob);
    // +4 for TSV header
    if (decoded_len != sizeof(struct platform_info_blob) + 4) {
        sgxlkl_warn("Invalid platform blob, expected length: %lu, actual length: %lu, sizeof(struct platform_info_blob): %lu.\n", sizeof(struct platform_info_blob) + 4, decoded_len, sizeof(struct platform_info_blob));
        return;
    }
    struct platform_info_blob *pi = (struct platform_info_blob *) (decoded_blob + 4);

    sgxlkl_info(" EPID group flags: 0x%x\n", pi->sgx_epid_group_flags);
    sgxlkl_info(" TCB evaluation flags: 0x%x%x\n", pi->sgx_tcb_evaluation_flags[0], pi->sgx_tcb_evaluation_flags[1]);
    sgxlkl_info(" PSE evaluation flags: 0x%x%x\n", pi->pse_evaluation_flags[0], pi->pse_evaluation_flags[1]);

    free(decoded_blob);
}

/** Turns a binary quote into an attestation verification report.

  Communicates with Intel Attestation Service via its HTTP REST interface.
*/
int ias_get_attestation_verification_report(
        const sgx_quote_t* quote,
        const uint32_t quote_size,
        const struct attestation_config* attn_config,
        attestation_verification_report_t* attn_report,
        int verbose) {
    CURL *curl;
    CURLcode res;
    int ret = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        if (getenv_bool("SGXLKL_IAS_ATTEST_VERBOSE", 0))
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        char url[512];
        int pret = snprintf(url, sizeof(url), "https://%s/attestation/v3/report",
                            attn_config->ias_server);
        assert(pret < (int) sizeof(url));
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        char buf[128];
        int rc = snprintf(buf, sizeof(buf), "Ocp-Apim-Subscription-Key: %.32s",
                          attn_config->ias_subscription_key);
        assert(rc < (int) sizeof(buf));

        headers = curl_slist_append(headers, buf);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        const char json_template[] = "{\"isvEnclaveQuote\":\"%s\"}";
        unsigned char quote_base64[quote_size * 2];
        uint32_t quote_base64_len = sizeof(quote_base64);
        char json[quote_size * 2];

        base64_encode_internal((uint8_t*) quote, quote_size,
                      quote_base64, &quote_base64_len);

        snprintf(json, sizeof(json), json_template, quote_base64);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);

        struct buffer_and_size header = {(char*) malloc(1), 0};
        struct buffer_and_size body = {(char*) malloc(1), 0};

        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, accumulate_function);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, accumulate_function);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

        /* Perform the request. */
        if (verbose)
            sgxlkl_info("Sending IAS request...\n");
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK) {
            sgxlkl_warn("Failed to request IAS attestation report: %s\n",
                        curl_easy_strerror(res));
            ret = 1;
            goto out;
        }

        /* Check response code */
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code != HTTP_STATUS_OK) {
            sgxlkl_warn("IAS attestation report request failed with HTTP code %ld%s. Run with SGXLKL_IAS_ATTEST_VERBOSE=1 for detailed IAS request and response output.\n",
                        response_code,
                        response_code == HTTP_STATUS_BAD_REQUEST ? BAD_REQUEST_INFO : "");
            ret = 1;
            goto out;
        }

        if (verbose)
            parse_response_body(body.data, body.len);

        /* Extract report signature and print advisory info if verbose == 1 */
        parse_response_header(header.data, header.len,
                              attn_report->ias_report_signature,
                              sizeof(attn_report->ias_report_signature),
                              &attn_report->ias_report_signature_len,
                              verbose);

        attn_report->ias_report_len = sizeof(attn_report->ias_report);
        assert(body.len <= attn_report->ias_report_len);
        memcpy(attn_report->ias_report, body.data, body.len);
        attn_report->ias_report_len = body.len;

        /* Extract certificates */
        extract_certificates_from_response_header(curl,
                                                  header.data, header.len,
                                                  attn_report);

out:
        /* Cleanup */
        curl_easy_cleanup(curl);

        free(header.data);
        free(body.data);
    }

    curl_global_cleanup();

    return ret;
}
