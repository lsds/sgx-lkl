#ifndef ATTEST_IAS_H
#define ATTEST_IAS_H

#include <sgx_quote.h>
#include "attest.h"

typedef struct {
    uint8_t ias_report[2*1024];
    uint32_t ias_report_len;
    uint8_t ias_sign_ca_cert[2*1024];
    uint32_t ias_sign_ca_cert_len;
    uint8_t ias_sign_cert[2*1024];
    uint32_t ias_sign_cert_len;
    uint8_t ias_report_signature[2*1024];
    uint32_t ias_report_signature_len;
} attestation_verification_report_t;


int ias_get_attestation_verification_report(
    const sgx_quote_t* quote,
    const uint32_t quote_size,
    const struct attestation_config* attestation_config,
    attestation_verification_report_t* attn_report,
    int verbose
);
#endif /* ATTEST_IAS_H */
