#include <unistd.h>
#include <sgx_uae_service.h>
#include <sgx_report.h>
#include <internal/se_quote_internal.h>

#define AESM_SOCKET_PATH "/var/run/aesmd/aesm.socket"

sgx_quote_t *aesm_alloc_quote(uint32_t *sz);

int aesm_init_quote(
    sgx_target_info_t *target_info, // out
    sgx_epid_group_id_t *gid // out
);

int aesm_get_quote(
    sgx_spid_t *spid, // in
    sgx_quote_sign_type_t quote_type, // in
    sgx_report_t* report, // in
    sgx_quote_t* quote, // out
    uint32_t quote_size
);
