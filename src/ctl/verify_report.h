#ifndef _VERIFY_H_
#define _VERIFY_H_

#include <sgx_quote.h>
#include "attest_ias.h"

void get_quote_from_report(const uint8_t* report /* in */,
                           const int report_len  /* in */,
                           sgx_quote_t* quote);

int verify_quote(sgx_quote_t *quote, const char *mrenclave_hex, const char *mrsigner_hex);
int verify_report(int strict, const char *ias_sign_ca_cert_pem, attestation_verification_report_t *attn_report,
                  const char *mrenclave, const char *mrsigner, uint64_t nonce);
#endif
