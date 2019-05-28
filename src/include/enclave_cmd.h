#ifndef ENCLAVE_CMD_H
#define ENCLAVE_CMD_H

#include <netinet/in.h>
#include <pthread.h>
#include "sgxlkl_app_config.h"
#ifdef SGXLKL_HW
#include "sgx_enclave_config.h"
#include "attest_ias.h"
#endif /* SGXLKL_HW */

typedef struct cmd_server_config {
    struct sockaddr_in addr;         /* IP and port the server will listen on. */
    sgxlkl_app_config_t *app_config; /* If not NULL the server will wait for an
                                        incoming run request, fill app_config
                                        and signal the receipt via signal to
                                        run_cv. Only one run request will be
                                        accepted. */
    pthread_mutex_t *run_mtx;        /* Mutex to protect run_cv */
    pthread_cond_t *run_cv;          /* Condition variable used to signal the
                                        receipt of a run command. */
    int attest_only;                 /* If specified, this instance should only
                                        respond to attest requests. */
#ifdef SGXLKL_HW
    attestation_info_t *att_info;    /* Attestation info (quote and
                                        (optionally) IAS attestation report for
                                        the current enclave. */
#endif
} cmd_server_config_t;

void enclave_cmd_server_run(cmd_server_config_t *config);
void enclave_cmd_servers_stop(void);

#endif /* ENCLAVE_CMD_H */
