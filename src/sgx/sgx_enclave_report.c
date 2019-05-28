#ifdef SGXLKL_HW

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_report.h>
#include <trts_inst.h>
#include <util.h> // ROUND_TO macro
#include <se_memcpy.h>

#include "sgx_enclave_config.h"
#include "sgxlkl_util.h"

void enclave_report(
    sgx_target_info_t* target_info,
    sgx_report_data_t* report_data,
    sgx_report_t* report
)
{
    assert(target_info != NULL);
    assert(report_data != NULL);
    assert(report != NULL);

    /* This code is adapted from SDK's sgx_create_report() in
     * sgx_create_report.cpp */
    size_t size = ROUND_TO(sizeof(sgx_target_info_t), TARGET_INFO_ALIGN_SIZE) +
                  ROUND_TO(sizeof(sgx_report_data_t), REPORT_DATA_ALIGN_SIZE) +
                  ROUND_TO(sizeof(sgx_report_t), REPORT_ALIGN_SIZE);
    size += MAX(MAX(TARGET_INFO_ALIGN_SIZE, REPORT_DATA_ALIGN_SIZE), REPORT_ALIGN_SIZE) - 1;

    void *buffer = malloc(size);
    if (!buffer)
        sgxlkl_fail("Unable to allocate memory for enclave report.\n");

    memset(buffer, 0, size);
    size_t buf_ptr = (size_t) (buffer);

    buf_ptr = ROUND_TO(buf_ptr, REPORT_ALIGN_SIZE);
    sgx_report_t *tmp_report = (sgx_report_t*) (buf_ptr);
    buf_ptr += sizeof(*tmp_report);

    buf_ptr = ROUND_TO(buf_ptr, TARGET_INFO_ALIGN_SIZE);
    sgx_target_info_t *tmp_target_info = (sgx_target_info_t*) (buf_ptr);
    buf_ptr += sizeof(*tmp_target_info);

    buf_ptr = ROUND_TO(buf_ptr, REPORT_DATA_ALIGN_SIZE);
    sgx_report_data_t *tmp_report_data = (sgx_report_data_t*) (buf_ptr);

    // Copy data from user buffer to the aligned memory
    memcpy_s(tmp_target_info, sizeof(*tmp_target_info), target_info, sizeof(*target_info));
    memcpy_s(tmp_report_data, sizeof(*tmp_report_data), report_data, sizeof(*report_data));

    ereport((void *)tmp_target_info, (char *)tmp_report_data, (char *)tmp_report);
    memcpy_s(report, sizeof(*report), tmp_report, sizeof(*tmp_report));

    free(buffer);
}

#endif /* SGXLKL_HW */
