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
    const char *ias_key_file;
    const char *ias_cert_file;
    /* Domain name/IP and port, e.g.,
       test-as.sgx.trustedservices.intel.com:443 */
    const char *ias_server;
};
#endif /* _ATTEST_H_ */
