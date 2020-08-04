#ifndef VERIFY_CERT_H
#define VERIFY_CERT_H

#include "../public/host_verify.h"

oe_result_t _oe_verify_attestation_certificate(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_identity_verify_callback_t enclave_identity_callback,
    void* arg);

#endif
