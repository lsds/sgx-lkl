#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "attest_ias.h"
#include "json_util.h"
#include "protobuf-c-rpc/protobuf-c-rpc-dispatch.h"
#include "protobuf-c-rpc/protobuf-c-rpc.h"
#include "sgxlkl_ctl.pb-c.h"
#include "sgxlkl_util.h"
#include "verify_report.h"
#include "wireguard.h"

static const char *ias_sign_ca_cert_path = NULL;
static const char *mrenclave = NULL;
static const char *mrsigner = NULL;
static uint64_t nonce = 0;
static int spid_provided = 0;
static int strict_mode = 0;
static int print_wg_key = 0;
static int force_ias_attestation = 0;

#define DEFAULT_IAS_SERVER "api.trustedservices.intel.com/sgx/dev"
static struct attestation_config attn_config = {
    // Default values
    .ias_server = DEFAULT_IAS_SERVER,
    .quote_type = SGX_UNLINKABLE_SIGNATURE
};

static void usage(char *cmd, int exit_code) {
    printf(
        "Usage: %s [attest|run|addpeer] --server=HOST:PORT [--app=<json-path>] \n"
        "[--ias-sign-ca-cert=<pem-ca-cert-path] [--ias-spid=<SPID>]\n"
        "[--ias-server=<host:port>] [--ias-quote-type=<\"Unlinkable\"|\"Linkable\">]\n"
        "[--ias-skey=<ias-subscription-key>]\n"
        "[--force-ias-attestation] [--mrenclave=<expected-mrenclave>]\n"
        "[--mrsigner=<expected-mrsigner>] [--nonce=<nonce>] [--strict]\n"
        "[--print-wg-key] [--key=<peer-key>] [--endpoint=<peer-endpoint>]\n"
        "[--allowedips=<peer-allowedips>]\n"
        "\n"
        "Send attestation and control requests to a remote SGX-LKL enclave.\n"
        "\n"
        "Actions\n"
        " attest                      Receive quote/attestation report and verify it.\n"
        " run                         Send application run request.\n"
        " addpeer                     Adds a new Wireguard peer.\n"
        "\n"
        "General options\n"
        " -u, --usage                 Print this help text.\n"
        " -h, --help                  Print this help text.\n"
        " -s, --server=HOST:PORT      Hostname/IP and Port of SGX-LKL endpoint.\n"
        "\n"
        "Attestation ('attest') options\n"
        " -i, -ias-spid=<SPID>        IAS service provider ID (SPID) as HEX string to\n"
        "                             use for IAS verification.\n"
        " -I, --ias-sign-ca-cert=<path>\n"
        "                             Path to the IAS signing CA certificate\n"
        "                             in PEM format to use for IAS verification.\n"
        " -e, --ias-server<host:port> Hostname/IP and port of IAS server to use for\n"
        "                             verification (Default:\n"
        "                             api.trustedservices.intel.com/sgx/dev).\n"
        " -q, --ias-quote-type=<type> Quote type, either \"Unlinkable\" or \"Linkable\"\n"
        "                             (Default: \"Unlinkable\").\n"
        " -k, --ias-skey=<hex>        IAS subscription key to use for IAS\n"
        "                             verification.\n"
        " -f, --force-ias-attestation If specified, a new IAS report is requested\n"
        "                             regardless of whether a server-side report exists.\n"
        " -E, --mrenclave=<hex>       Expected MRENCLAVE measurement as HEX string.\n"
        " -g, --mrsigner=<hex>        Expected MRSIGNER measurement as HEX string.\n"
        " -n, --nonce=<nonce>         Expected Nonce specified at start of SGX-LKL.\n"
        " -S, --strict                If specified, terminate after first quote/IAS\n"
        "                             verification error. Without --strict, both\n"
        "                             GROUP_OUT_DATE and CONFIGURATION_NEEDED, which\n"
        "                             indicate that the enclave quote has been verified"
        "                             successfully but the platform software is out of\n"
        "                             date, are considered acceptable IAS quote status\n"
        "                             values.\n"
        " -P, --print-wg-key          If specified, the enclave's public Wireguard key\n"
        "                             is written to stdout after attestation.\n"
        "\n"
        "Run ('run') options\n"
        " -a, --app=<json-path>       Path to JSON file containing application\n"
        "                             configuration.\n"
        "\n"
        "Add peer ('addpeer') options\n"
        " -K, --key=<peer-key>        Public key of Wireguard peer to add.\n"
        " -p, --endpoint=<host:port>  Public endpoint of Wireguard peer to add.\n"
        " -A, --allowedips=<ip/mask,...>\n"
        "                              Allowed IPs of Wireguard peer to add in the format\n"
        "                             \"ip1/mask1,ip2/mask2,...\".\n"
    , cmd);
    exit(exit_code);
}

static void handle_addpeers_response(const Sgxlkl__AddPeersResult *result,
                                void *closure_data) {
    if (result == NULL) {
        printf ("Error processing request.\n");
        goto out;
    }

    switch(result->err) {
        case SGXLKL__ERROR__SUCCESS:
            fprintf(stderr, "Request successful.\n");
            break;
        case SGXLKL__ERROR__INTERNAL:
            sgxlkl_warn("Failed to add peer due to internal server error: %s\n", result->err_msg);
            break;
        case SGXLKL__ERROR__NOT_PERMITTED:
            sgxlkl_warn("Request not permitted: %s\n", result->err_msg);
            break;
        default:
            sgxlkl_err("Unknown error.\n");
            break;
    }

out:
    *(protobuf_c_boolean *)closure_data = 1;
}

static void do_addpeers(ProtobufCService *service, char *peer_key,
                        char *peer_endpoint, char *peer_allowedips) {
    Sgxlkl__AddPeersRequest req = SGXLKL__ADD_PEERS_REQUEST__INIT;
    // TODO support adding multiple peers at once. This is already supported by
    // the endpoint.
    req.n_peers = 1;

    Sgxlkl__Peer *peer;
    if(!(peer = malloc(sizeof(*peer))))
        sgxlkl_fail("Failed to allocated memory for peer.\n");
    sgxlkl__peer__init(peer);
    peer->key = peer_key;
    peer->endpoint = peer_endpoint;
    peer->allowed_ips = peer_allowedips;

    if (!(req.peers = malloc(sizeof(Sgxlkl__Peer*) * req.n_peers)))
        sgxlkl_fail("Failed to allocated memory for peer array.\n");
    req.peers[0] = peer;

    protobuf_c_boolean is_done = 0;
    sgxlkl__control__add_peers(service, &req, handle_addpeers_response, &is_done);
    while (!is_done)
        protobuf_c_rpc_dispatch_run(protobuf_c_rpc_dispatch_default());

    free(peer);
    free(req.peers);
}

static void handle_attest_response(const Sgxlkl__AttestResult *result,
                                void *closure_data) {
    if (result == NULL) {
        printf ("Error processing request.\n");
        goto out;
    }

    attestation_verification_report_t *report = malloc(sizeof(*report));
    switch(result->err) {
        case SGXLKL__ERROR__SUCCESS:
            fprintf(stderr, "Request successful.\n");

            if (result->quote.len && (!result->ias_report.len || force_ias_attestation)) {
                if (!spid_provided)
                    sgxlkl_warn("No IAS SPID provided, skipping IAS verification.\n");
                else if (!attn_config.ias_subscription_key)
                    sgxlkl_warn("No IAS subscription key provided (via --ias-skey), skipping IAS verification.\n");

                if (spid_provided && attn_config.ias_subscription_key) {
                    if (ias_get_attestation_verification_report((sgx_quote_t *)result->quote.data,
                                                            result->quote.len,
                                                        &attn_config,
                                                        report,
                                                        1 /* verbose */)) {
                        sgxlkl_fail("Failed to retrieve IAS attestation report.\n");
                    }
                } else {
                    if (verify_quote((sgx_quote_t *)result->quote.data, mrenclave, mrsigner))
                        exit(EXIT_FAILURE);
                    goto out;
                }
            } else if (result->ias_report.len) {
                assert(result->ias_report.len <= sizeof(report->ias_report));
                assert(result->ias_sign_ca_cert.len <= sizeof(report->ias_sign_ca_cert));
                assert(result->ias_sign_cert.len <= sizeof(report->ias_sign_cert));
                assert(result->ias_report_signature.len <= sizeof(report->ias_report_signature));
                memcpy(report->ias_report, result->ias_report.data, result->ias_report.len);
                report->ias_report_len = result->ias_report.len;
                memcpy(report->ias_sign_ca_cert, result->ias_sign_ca_cert.data, result->ias_sign_ca_cert.len);
                report->ias_sign_ca_cert_len = result->ias_sign_ca_cert.len;
                memcpy(report->ias_sign_cert, result->ias_sign_cert.data, result->ias_sign_cert.len);
                report->ias_sign_cert_len = result->ias_sign_cert.len;
                memcpy(report->ias_report_signature, result->ias_report_signature.data, result->ias_report_signature.len);
                report->ias_report_signature_len = result->ias_report_signature.len;
            } else {
                sgxlkl_warn("Could not attest. No quote or attestation report provided.\n");
                goto out;
            }

            if (verify_report(strict_mode, ias_sign_ca_cert_path, report, mrenclave, mrsigner, 0)) {
                sgxlkl_fail("Verification of quote and attestation report failed!\n");
            } else {
                sgxlkl_info("Verification of quote and attestation report successful.\n");
            }

            sgx_quote_t quote;
            get_quote_from_report(report->ias_report, report->ias_report_len, &quote);
            struct sgxlkl_report_data *report_data = (struct sgxlkl_report_data *) &quote.report_body.report_data;
            wg_key_b64_string key;
            wg_key_to_base64(key, report_data->wg_public_key);
            sgxlkl_info("Enclave report data:\n");
            sgxlkl_info("  Nonce: %"PRIu64"\n", report_data->nonce);
            sgxlkl_info("  Public wireguard key: %s\n", key);

            if (nonce && nonce != report_data->nonce)
                    sgxlkl_fail("Nonce mismatch! Expected nonce: %"PRIu64"\n", nonce);

            if (print_wg_key)
                printf("%s\n", key);

            free(report);
            break;
        case SGXLKL__ERROR__SIM_MODE:
            sgxlkl_fail("Could not attest. Enclave runs in simulation mode.\n");
            break;
        case SGXLKL__ERROR__REP_NOT_AVAILABLE:
            sgxlkl_fail("Could not attest. Attestation report is unavailable.\n");
            break;
        default:
            sgxlkl_fail("Unknown error.\n");
            break;
    }

out:
    *(protobuf_c_boolean *)closure_data = 1;
}

static void do_attest(ProtobufCService *service) {
    Sgxlkl__AttestRequest req = SGXLKL__ATTEST_REQUEST__INIT;
    protobuf_c_boolean is_done = 0;
    sgxlkl__control__attest(service, &req, handle_attest_response, &is_done);
    while (!is_done)
        protobuf_c_rpc_dispatch_run(protobuf_c_rpc_dispatch_default());
}

static void handle_run_response(const Sgxlkl__RunResult *result,
                                void *closure_data) {
    if (result == NULL) {
        sgxlkl_err("Error processing response to run request.\n");
        goto out;
    }

    switch(result->err) {
        case SGXLKL__ERROR__SUCCESS:
            sgxlkl_info("Request successful.\n");
            break;
        case SGXLKL__ERROR__PARSE:
            sgxlkl_fail("Error parsing the configuration: %s\n", result->err_msg);
            break;
        case SGXLKL__ERROR__APP_RUNNING:
            sgxlkl_fail("Application is already running. Request is ignored.\n");
            break;
        case SGXLKL__ERROR__NOT_PERMITTED:
            sgxlkl_fail("Request not permitted: %s\n", result->err_msg);
            break;
        default:
            sgxlkl_fail("Unknown error.\n");
            break;
    }

out:
    *(protobuf_c_boolean *)closure_data = 1;
}

static void do_run(ProtobufCService *service, const char *app_config_path) {
    // Read app config
    int fd;
    if ((fd = open(app_config_path, O_RDONLY)) < 0)
        sgxlkl_fail("Failed to open application configuration file: %s\n", strerror(errno));

    off_t len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char *config = (char *) malloc(len + 1);
    ssize_t ret;
    int off = 0;
    while ((ret = read(fd, &config[off], len - off)) > 0) {
        off += ret;
    }
    config[len] = 0;

    if (ret < 0)
        sgxlkl_fail("Error reading application configuration file: %s\n", strerror(errno));

    close(fd);

    Sgxlkl__RunRequest req = SGXLKL__RUN_REQUEST__INIT;
    protobuf_c_boolean is_done = 0;
    req.json_config = config;
    sgxlkl__control__run(service, &req, handle_run_response, &is_done);
    while (!is_done)
        protobuf_c_rpc_dispatch_run(protobuf_c_rpc_dispatch_default());
}

int main(int argc, char**argv) {
    ProtobufCService *service;
    ProtobufC_RPC_Client *client;
    ProtobufC_RPC_AddressType address_type = PROTOBUF_C_RPC_ADDRESS_TCP;
    const char *action = NULL, *host = NULL, *config_path = NULL, *app_config_path = NULL;
    char *spid = NULL, *peer_key = NULL, *peer_endpoint = NULL, *peer_allowedips = NULL, *endptr;
    ssize_t spid_len;

    static struct option long_options[] = {
        {"usage",                 no_argument,       0, 'u' },
        {"help",                  no_argument,       0, 'h' },
        {"server",                required_argument, 0, 's' },
        {"app",                   required_argument, 0, 'a' },
        {"ias-spid",              required_argument, 0, 'i' },
        {"ias-quote-type",        required_argument, 0, 'q' },
        {"ias-server",            required_argument, 0, 'e' },
        {"ias-sign-ca-cert",      required_argument, 0, 'I' },
        {"ias-skey",              required_argument, 0, 'k' },
        {"force-ias-attestation", no_argument,       0, 'f' },
        {"mrenclave",             required_argument, 0, 'E' },
        {"mrsigner",              required_argument, 0, 'g' },
        {"nonce",                 required_argument, 0, 'n' },
        {"strict",                no_argument,       0, 'S' },
        {"print-wg-key",          no_argument,       0, 'P' },
        {"key",                   required_argument, 0, 'K' },
        {"endpoint",              required_argument, 0, 'p' },
        {"allowedips",            required_argument, 0, 'A' },
        {0,                       0,                 0,  0  }
    };

    int c;
    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "uhs:c:a:i:q:k:C:e:I:fe:g:n:S:P:t:K:p:A", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'u':
        case 'h':
            usage(argv[0], EXIT_SUCCESS);
        case 's':
            host = optarg;
            break;
        case 'a':
            app_config_path = optarg;
            break;
        case 'i':
            spid_len = hex_to_bytes(optarg, &spid);
            if (spid_len != sizeof(sgx_spid_t))
                fprintf(stderr, "Provided IAS SPID \"%s\" invalid.\n", optarg);
            memcpy(&attn_config.spid, spid, spid_len);
            spid_provided = 1;
            break;
        case 'q':
            attn_config.quote_type = !strcmp(optarg, "Unlinkable") ? SGX_UNLINKABLE_SIGNATURE : SGX_LINKABLE_SIGNATURE;
            break;
        case 'e':
            attn_config.ias_server = optarg;
            break;
        case 'k':
            attn_config.ias_subscription_key = optarg;
            break;
        case 'I':
            ias_sign_ca_cert_path = optarg;
            break;
        case 'f':
            force_ias_attestation = 1;
            break;
        case 'E':
            mrenclave = optarg;
            break;
        case 'g':
            mrsigner = optarg;
            break;
        case 'n':
            errno = 0;
            nonce = (uint64_t) strtoull(optarg, &endptr, 10);
            if (nonce == ULONG_MAX && errno == ERANGE)
                sgxlkl_fail("Failed to parse nonce '%s' (not a valid unsigned 64-bit integer): %s\n", optarg, strerror(errno));
            break;
        case 'P':
            print_wg_key = 1;
            break;
        case 'S':
            strict_mode = 1;
            break;
        case 'K':
            peer_key = optarg;
            break;
        case 'p':
            peer_endpoint = optarg;
            break;
        case 'A':
            peer_allowedips = optarg;
            break;
        default:
            fprintf(stderr, "Unknown command line option: %c\n", c);
            usage(argv[0], EXIT_FAILURE);
         }
    }

    if (argc <= optind) {
        fprintf(stderr, "No action specified.\n");
        usage(argv[0], EXIT_FAILURE);
    }

    if (!host) {
        fprintf(stderr, "No server specified via --server.\n");
        usage(argv[0], EXIT_FAILURE);
    }

    service = protobuf_c_rpc_client_new(address_type, host, &sgxlkl__control__descriptor, NULL);
    if (service == NULL) {
        fprintf(stderr, "Error creating client.\n");
        exit(1);
    }
    client = (ProtobufC_RPC_Client *) service;

    fprintf (stderr, "Connecting to %s... ", host);
    while (!protobuf_c_rpc_client_is_connected(client))
        protobuf_c_rpc_dispatch_run(protobuf_c_rpc_dispatch_default());
    fprintf (stderr, "done.\n");


    action = argv[optind];
    if (!strcmp(action, "attest"))
        do_attest(service);
    else if (!strcmp(action, "run"))
        do_run(service, app_config_path);
    else if (!strcmp(action, "addpeer")) {
        if (!peer_key) {
            fprintf(stderr, "No peer key specified via --key.\n");
            usage(argv[0], EXIT_FAILURE);
        /*} else if (!peer_endpoint) {
            fprintf(stderr, "No peer endpoint specified via --endpoint.\n");
            usage(argv[0], EXIT_FAILURE);*/
        } else if (!peer_allowedips) {
            fprintf(stderr, "No allowed IPs specified for peer via --allowedips.\n");
            usage(argv[0], EXIT_FAILURE);
        }
        do_addpeers(service, peer_key, peer_endpoint, peer_allowedips);
    } else {
        fprintf(stderr, "Unknown action: %s\n", action);
        usage(argv[0], EXIT_FAILURE);
    }

    return 0;
}
