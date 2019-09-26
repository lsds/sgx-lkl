#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>

#include "enclave_cmd.h"
#include "lthread.h"
#include "queue.h"
#include "protobuf-c-rpc/protobuf-c-rpc.h"
#include "sgx_enclave_config.h"
#include "sgxlkl_app_config.h"
#include "sgxlkl_ctl.pb-c.h"
#include "sgxlkl_debug.h"
#include "sgxlkl_util.h"
#include "wireguard_util.h"

#define ERR_MSG_ATTEST_ONLY "This is an attest-only endpoint"

static int _servers_stopped = 0;

struct cmd_server {
    Sgxlkl__Control_Service *service;
    struct cmd_server_config config;
    int running;
    SLIST_ENTRY(cmd_server) entries;
};

SLIST_HEAD(_servers_head, cmd_server) servers =
     SLIST_HEAD_INITIALIZER(servers);

static struct cmd_server *srv_from_service(Sgxlkl__Control_Service *service) {
    struct cmd_server *srv;
    SLIST_FOREACH(srv, &servers, entries) {
        if (srv->service == service)
            return srv;
    }

    // Should never happen
    assert(0);
    return NULL;
}

/* Handle add peers request
 *
 * Adds new Wireguard peers.
 */
static void cmd__add_peers(Sgxlkl__Control_Service *service,
                  const Sgxlkl__AddPeersRequest   *req,
                  Sgxlkl__AddPeersResult_Closure  closure,
                  void                       *closure_data) {
    struct cmd_server_config *server_config = &srv_from_service(service)->config;
    Sgxlkl__AddPeersResult result = SGXLKL__ADD_PEERS_RESULT__INIT;

    // If server is configured to attest only, fail here.
    if (server_config->attest_only) {
        result.err = SGXLKL__ERROR__NOT_PERMITTED;
        result.err_msg = ERR_MSG_ATTEST_ONLY;
        closure (&result, closure_data);
        return;
    }

    // Get WG device
    wg_device *wg_dev;
    if (wg_get_device(&wg_dev, "wg0")) {
        result.err = SGXLKL__ERROR__INTERNAL;
        result.err_msg = strerror(errno);
        closure(&result, closure_data);
        return;
    }

    // Get peers from request
    enclave_wg_peer_config_t new_peers[req->n_peers];
    for (int i = 0; i < req->n_peers; i++) {
        Sgxlkl__Peer *peer = req->peers[i];
        SGXLKL_VERBOSE("Received request to add peer %s.\n", peer->key);
        new_peers[i].key = peer->key;
        new_peers[i].allowed_ips = peer->allowed_ips;
        new_peers[i].endpoint = peer->endpoint;
    }

    // Add peers to wg0
    if (wgu_add_peers(wg_dev, new_peers, req->n_peers, 1)) {
        result.err = SGXLKL__ERROR__INTERNAL;
        result.err_msg = strerror(errno);
    }

    closure(&result, closure_data);
}

/* Handle attest request
 *
 * Return quote and IAS attestation report if available
 */
static void cmd__attest(Sgxlkl__Control_Service *service,
                  const Sgxlkl__AttestRequest   *req,
                  Sgxlkl__AttestResult_Closure  closure,
                  void                       *closure_data) {
    struct cmd_server_config *server_config = &srv_from_service(service)->config;
    Sgxlkl__AttestResult result = SGXLKL__ATTEST_RESULT__INIT;

#ifdef SGXLKL_HW
    // TODO Handle potential TOCTOU attacks here
    if (server_config->att_info->quote) {
        result.quote.len = server_config->att_info->quote_size;
        result.quote.data = (uint8_t *)server_config->att_info->quote;
    } else
        result.err = SGXLKL__ERROR__REP_NOT_AVAILABLE;

    attestation_verification_report_t *report = server_config->att_info->ias_report;

    if (report) {
        result.ias_report.len = report->ias_report_len;
        result.ias_report.data = report->ias_report;
        result.ias_sign_ca_cert.len = report->ias_sign_ca_cert_len;
        result.ias_sign_ca_cert.data = report->ias_sign_ca_cert;
        result.ias_sign_cert.len = report->ias_sign_cert_len;
        result.ias_sign_cert.data = report->ias_sign_cert;
        result.ias_report_signature.len = report->ias_report_signature_len;
        result.ias_report_signature.data = report->ias_report_signature;
        result.err = SGXLKL__ERROR__SUCCESS;
    }
#else
    result.err = SGXLKL__ERROR__SIM_MODE;
#endif

    closure(&result, closure_data);
}

/* Handle run request
 *
 * Parse JSON application configuration and launch application.
 */
static void cmd__run(Sgxlkl__Control_Service *service,
                  const Sgxlkl__RunRequest   *req,
                  Sgxlkl__RunResult_Closure  closure,
                  void                       *closure_data) {
    struct cmd_server_config *server_config = &srv_from_service(service)->config;
    char *err_desc = NULL;
    Sgxlkl__RunResult result = SGXLKL__RUN_RESULT__INIT;

    // If server is configured to attest only, fail here.
    if (server_config->attest_only) {
        result.err = SGXLKL__ERROR__NOT_PERMITTED;
        result.err_msg = ERR_MSG_ATTEST_ONLY;
        closure (&result, closure_data);
        return;
    }

    // Check for missing configuration
    if (req == NULL || req->json_config == NULL) {
        closure (NULL, closure_data);
        return;
    }

    sgxlkl_app_config_t *app_config = server_config->app_config;
    if (app_config == NULL) {
        result.err = SGXLKL__ERROR__APP_RUNNING;
    } else if (!parse_sgxlkl_app_config_from_str(req->json_config, app_config, &err_desc)) {
        if (!app_config->disks) {
            result.err = SGXLKL__ERROR__PARSE;
            result.err_msg = "Missing disk configuration";
        } else {
            int ret;
            if ((ret = pthread_mutex_lock(server_config->run_mtx)) ||
                (ret = pthread_cond_signal(server_config->run_cv))) {
                result.err = SGXLKL__ERROR__INTERNAL;
                result.err_msg = strerror(errno);
            } else {
                pthread_mutex_unlock(server_config->run_mtx);
                app_config = NULL;
                result.err = SGXLKL__ERROR__SUCCESS;
            }
        }
    } else {
        result.err = SGXLKL__ERROR__PARSE;
        result.err_msg = err_desc;
    }

    closure (&result, closure_data);

    if (err_desc)
        free(err_desc);
}

/*
 * Memory pointed to by config will be freed within this function!  This is
 * done as enclave_cmd_server_run is most likely run in a new thread and the
 * parent thread would not know for how long to keep config around before it had
 * been parsed/used by this function and can be free'd.
 */
void enclave_cmd_server_run(cmd_server_config_t *config) {
    // Ensure this is still supposed to run. This function will likely be
    // called in a separate thread. If SGX-LKL fails at startup and this
    // function is run after 'enclave_cmd_servers_stop' has been called, trying
    // to start the server is pointless and will most likely lead to additional
    // failures due to disks having been unmounted/the kernel having been
    // shutdown already.
    if (_servers_stopped) return;

    Sgxlkl__Control_Service service = SGXLKL__CONTROL__INIT(cmd__);
    struct sockaddr_in *addr = &config->addr;
    ProtobufC_RPC_Server *server;
    ProtobufC_RPC_AddressType address_type = PROTOBUF_C_RPC_ADDRESS_TCP;
    ProtobufCRPCDispatch *dispatch = protobuf_c_rpc_dispatch_default_new();
    // Check again as protobuf_c_rpc_dispatch_default_new might yield.
    if (_servers_stopped) return;
    server = protobuf_c_rpc_server_new(address_type,
                                       "sgxlkl_cmd",
                                       addr,
                                       (ProtobufCService *) &service,
                                       dispatch);

    struct cmd_server *cmd_srv = malloc(sizeof(*cmd_srv));
    if (!cmd_srv)
        sgxlkl_fail("Failed to allocate memory for cmd_server struct.\n");
    cmd_srv->service = &service;
    cmd_srv->config = *config;
    // No need to keep the passed in config in memory after this.
    free(config);

    cmd_srv->running = 1;
    SLIST_INSERT_HEAD(&servers, cmd_srv, entries);

    while(!_servers_stopped && cmd_srv->running)
      protobuf_c_rpc_dispatch_run(dispatch);

    protobuf_c_rpc_server_destroy((ProtobufC_RPC_Server *)server, 1);
    free(cmd_srv);
}

void enclave_cmd_servers_stop(void) {
    _servers_stopped = 1;
    struct cmd_server *srv;
    SLIST_FOREACH(srv, &servers, entries) {
        srv->running = 0;
    }
}
