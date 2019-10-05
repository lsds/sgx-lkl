#ifndef _ATTEST_H_
#define _ATTEST_H_

#include <sgx_quote.h>

struct sgxlkl_report_data {
    uint8_t wg_public_key[32];
    uint64_t nonce;
    uint8_t reserved[24];
};

struct attestation_config {
    sgx_spid_t spid;
    sgx_quote_sign_type_t quote_type;
    /* NULL-terminated string of domain name/IP, port and path prefix,
       e.g., api.trustedservices.intel.com/sgx/dev for development and
       api.trustedservices.intel.com/sgx for production. */
    const char *ias_server;
    const char *ias_subscription_key;
};
#endif /* _ATTEST_H_ */
