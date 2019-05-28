#ifndef SGX_ENCLAVE_REPORT_H
#define SGX_ENCLAVE_REPORT_H

#include <sgx_report.h>

void enclave_report(
    sgx_target_info_t* target_info,
    sgx_report_data_t* report_data,
    sgx_report_t* report
);

#endif /* SGX_ENCLAVE_REPORT_H */
