#include <assert.h>
#include <limits.h>
#include <string.h>

#include "json_util.h"
#include "sgx_enclave_config.h"
#include "sgxlkl_config.h"
#include "sgxlkl_util.h"

#define TYPE_CHAR 0
#define TYPE_UINT 1
#define TYPE_BOOL 2
#define TYPE_JSON 3

struct sgxlkl_config_uint_def {
    uint64_t val;
    uint64_t max;
};

struct sgxlkl_config_elem {
    char *env_key;
    char *json_key;
    int type;
    union {
        char *def_char;
        struct sgxlkl_config_uint_def def_uint;
        int def_bool;
    };
    int inited;
    union {
        uint64_t val_uint;
        char *val_char;
        int val_bool;
    };
};

static struct sgxlkl_config_elem sgxlkl_config[] = {
 /*  0 */ {"SGXLKL_APP_CONFIG",               "app_config",               TYPE_JSON, {.def_char = NULL}, 0},
 /*  1 */ {"SGXLKL_CMDLINE",                  "cmdline",                  TYPE_CHAR, {.def_char = ""}, 0},
 /*  2 */ {"SGXLKL_CWD",                      "cwd",                      TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_CWD}, 0},
 /*  3 */ {"SGXLKL_DEBUGMOUNT",               "debugmount",               TYPE_CHAR, {.def_char = NULL}, 0},
 /*  4 */ {"SGXLKL_ESPINS",                   "espins",                   TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_ESPINS, ULONG_MAX}}, 0},
 /*  5 */ {"SGXLKL_ESLEEP",                   "esleep",                   TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_ESLEEP, ULONG_MAX}}, 0},
 /*  6 */ {"SGXLKL_ETHREADS",                 "ethreads",                 TYPE_UINT, {.def_uint = {1, MAX_SGXLKL_ETHREADS}}, 0},
 /*  7 */ {"SGXLKL_ETHREADS_AFFINITY",        "ethreads_affinity",        TYPE_CHAR, {.def_char = NULL}, 0},
 /*  8 */ {"SGXLKL_GETTIME_VDSO",             "gettime_vdso",             TYPE_BOOL, {.def_bool = 1}, 0},
 /*  9 */ {"SGXLKL_GW4",                      "gw4",                      TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_GW4}, 0},
 /* 11 */ {"SGXLKL_GW6",                      "gw6",                      TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_GW6}, 0},
 /* 11 */ {"SGXLKL_HD",                       "hd",                       TYPE_CHAR, {.def_char = NULL}, 0},
 /* 12 */ {"SGXLKL_HD_KEY",                   "hd_key",                   TYPE_CHAR, {.def_char = NULL}, 0},
 /* 13 */ {"SGXLKL_HD_RO",                    "hd_readonly",              TYPE_BOOL, {.def_bool = 0}, 0},
 /* 14 */ {"SGXLKL_HDS",                      "hds",                      TYPE_CHAR, {.def_char = ""}, 0},
 /* 15 */ {"SGXLKL_HD_VERITY",                "hd_verity",                TYPE_CHAR, {.def_char = NULL}, 0},
 /* 16 */ {"SGXLKL_HD_VERITY_OFFSET",         "hd_verity_offset",         TYPE_CHAR, {.def_char = NULL}, 0}, //TODO: Change to uint64
 /* 17 */ {"SGXLKL_HEAP",                     "heap",                     TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_HEAP_SIZE, ULONG_MAX}}, 0},
 /* 18 */ {"SGXLKL_HOSTNAME",                 "hostname",                 TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_HOSTNAME}, 0},
 /* 19 */ {"SGXLKL_HOSTNET",                  "hostnet",                  TYPE_BOOL, {.def_bool = 0}, 0},
 /* 20 */ {"SGXLKL_IAS_CERT",                 "ias_cert",                 TYPE_CHAR, {.def_char = NULL}, 0},
 /* 21 */ {"SGXLKL_IAS_KEY_FILE",             "ias_key_file",             TYPE_CHAR, {.def_char = NULL}, 0},
 /* 22 */ {"SGXLKL_IAS_QUOTE_TYPE",           "ias_quote_type",           TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_IAS_QUOTE_TYPE}, 0},
 /* 23 */ {"SGXLKL_IAS_SERVER",               "ias_server",               TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_IAS_SERVER}, 0},
 /* 24 */ {"SGXLKL_IAS_SPID",                 "ias_spid",                 TYPE_CHAR, {.def_char = NULL}, 0},
 /* 25 */ {"SGXLKL_IP4",                      "ip4",                      TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_IP4}, 0},
 /* 26 */ {"SGXLKL_IP6",                      "ip6",                      TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_IP6}, 0},
 /* 27 */ {"SGXLKL_KERNEL_VERBOSE",           "kernel_verbose",           TYPE_BOOL, {.def_bool = 0}, 0},
 /* 28 */ {"SGXLKL_KEY",                      "key",                      TYPE_CHAR, {.def_char = NULL}, 0},
 /* 29 */ {"SGXLKL_MASK4",                    "mask4",                    TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_MASK4, 32}}, 0},
 /* 30 */ {"SGXLKL_MASK6",                    "mask6",                    TYPE_UINT, {.def_uint = DEFAULT_SGXLKL_MASK6}, 0},
 /* 31 */ {"SGXLKL_MAX_USER_THREADS",         "max_user_threads",         TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_MAX_USER_THREADS, MAX_SGXLKL_MAX_USER_THREADS}}, 0},
 /* 32 */ {"SGXLKL_MMAP_FILES",               "mmap_files",               TYPE_CHAR, {.def_char = "None"}, 0},
 /* 33 */ {"SGXLKL_NON_PIE",                  "non_pie",                  TYPE_BOOL, {.def_bool = 0}, 0},
 /* 34 */ {"SGXLKL_PRINT_APP_RUNTIME",        "print_app_runtime",        TYPE_BOOL, {.def_bool = 0}, 0},
 /* 35 */ {"SGXLKL_PRINT_HOST_SYSCALL_STATS", "print_host_syscall_stats", TYPE_BOOL, {.def_bool = 0}, 0},
 /* 36 */ {"SGXLKL_REAL_TIME_PRIO",           "real_time_prio",           TYPE_BOOL, {.def_bool = 0}, 0},
 /* 37 */ {"SGXLKL_REMOTE_ATTEST_PORT",       "remote_attest_port",       TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_REMOTE_ATTEST_PORT, USHRT_MAX}}, 0},
 /* 38 */ {"SGXLKL_REMOTE_CMD_PORT",          "remote_cmd_port",          TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_REMOTE_CMD_PORT, USHRT_MAX}}, 0},
 /* 39 */ {"SGXLKL_REMOTE_CMD_ETH0",          "remote_cmd_eth0",          TYPE_BOOL, {.def_bool = 0}, 0},
 /* 40 */ {"SGXLKL_REMOTE_CONFIG",            "remote_config",            TYPE_BOOL, {.def_bool = 0}, 0},
 /* 41 */ {"SGXLKL_REPORT_NONCE",             "report_nonce",             TYPE_UINT, {.def_uint = {0, ULONG_MAX}}, 0},
 /* 42 */ {"SGXLKL_SHMEM_FILE",               "shmem_file",               TYPE_CHAR, {.def_char = NULL}, 0},
 /* 43 */ {"SGXLKL_SHMEM_SIZE",               "shmem_size",               TYPE_UINT, {.def_uint = {0, 1024 * 1024 * 1024}}, 0},
 /* 44 */ {"SGXLKL_SIGPIPE",                  "sigpipe",                  TYPE_BOOL, {.def_bool = 0}, 0},
 /* 45 */ {"SGXLKL_SSLEEP",                   "ssleep",                   TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_SSLEEP, ULONG_MAX}}, 0},
 /* 46 */ {"SGXLKL_SSPINS",                   "sspins",                   TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_SSPINS, ULONG_MAX}}, 0},
 /* 47 */ {"SGXLKL_STACK_SIZE",               "stack_size",               TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_STACK_SIZE, ULONG_MAX}}, 0},
 /* 48 */ {"SGXLKL_STHREADS",                 "sthreads",                 TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_STHREADS, MAX_SGXLKL_STHREADS}}, 0},
 /* 49 */ {"SGXLKL_STHREADS_AFFINITY",        "sthreads_affinity",        TYPE_CHAR, {.def_char = NULL}, 0},
 /* 50 */ {"SGXLKL_TAP",                      "tap",                      TYPE_CHAR, {.def_char = NULL}, 0},
 /* 51 */ {"SGXLKL_TAP_MTU",                  "tap_mtu",                  TYPE_UINT, {.def_uint = {0, INT_MAX}}, 0},
 /* 52 */ {"SGXLKL_TAP_OFFLOAD",              "tap_offload",              TYPE_BOOL, {.def_bool = 0}, 0},
 /* 53 */ {"SGXLKL_TRACE_HOST_SYSCALL",       "trace_host_syscall",       TYPE_BOOL, {.def_bool = 0}, 0},
 /* 54 */ {"SGXLKL_TRACE_INTERNAL_SYSCALL",   "trace_internal_syscall",   TYPE_BOOL, {.def_bool = 0}, 0},
 /* 55 */ {"SGXLKL_TRACE_LKL_SYSCALL",        "trace_lkl_syscall",        TYPE_BOOL, {.def_bool = 0}, 0},
 /* 56 */ {"SGXLKL_TRACE_MMAP",               "trace_mmap",               TYPE_BOOL, {.def_bool = 0}, 0},
 /* 57 */ {"SGXLKL_TRACE_SYSCALL",            "trace_syscall",            TYPE_BOOL, {.def_bool = 0}, 0},
 /* 58 */ {"SGXLKL_TRACE_THREAD",             "trace_thread",             TYPE_BOOL, {.def_bool = 0}, 0},
 /* 59 */ {"SGXLKL_VERBOSE",                  "verbose",                  TYPE_BOOL, {.def_bool = 0}, 0},
 /* 60 */ {"SGXLKL_WG_IP",                    "wg_ip",                    TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_WG_IP}, 0},
 /* 61 */ {"SGXLKL_WG_PORT",                  "wg_port",                  TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_WG_PORT, USHRT_MAX}}, 0},
 /* 62 */ {"SGXLKL_WG_KEY",                   "wg_key",                   TYPE_CHAR, {.def_char = NULL}, 0},
 /* 63 */ {"SGXLKL_WG_PEERS",                 "wg_peers",                 TYPE_CHAR, {.def_char = ""}, 0},
};

static inline struct sgxlkl_config_elem *config_elem_by_key(const char *key) {
    for (int i = 0; i < sizeof(sgxlkl_config)/sizeof(sgxlkl_config[0]); i++) {
        if (!strcmp(sgxlkl_config[i].json_key, key))
            return &sgxlkl_config[i];
    }
    return NULL;
}

static int parse_sgxlkl_config_entry(const char *key, struct json_object *value, void *arg) {
    struct sgxlkl_config_elem *ce = config_elem_by_key(key);
    if (!ce) {
        sgxlkl_warn("Unknown configuration entry: %s\n", key);
        goto end;
    }

    int json_val_type = json_object_get_type(value);
    switch (json_val_type) {
        case json_type_boolean:
            if (ce->type != TYPE_BOOL) {
                sgxlkl_warn("Unexpected value for configuration key %s. Boolean expected.\n", key);
                goto end;
            } else {
                ce->val_bool = getenv_bool(ce->env_key, json_object_get_boolean(value));
            }
            break;
        case json_type_int:
            if (ce->type != TYPE_UINT) {
                sgxlkl_warn("Unexpected value for configuration key %s. Integer expected.\n", key);
                goto end;
            } else {
                ce->val_uint = getenv_uint64(ce->env_key, json_object_get_int64(value), ce->def_uint.max);
            }
            break;
        case json_type_string:
            // Size string, e.g. "12k"?
            if (ce->type == TYPE_UINT) {
                uint64_t val = size_str_to_uint64(json_object_get_string(value), ce->def_uint.val, ce->def_uint.max);
                ce->val_uint = getenv_uint64(ce->env_key, val, ce->def_uint.max);
            } else if (ce->type != TYPE_CHAR) {
                sgxlkl_warn("Unexpected value for configuration key %s. String expected.\n", key);
                goto end;
            } else {
                ce->val_char = getenv_str(ce->env_key, json_object_get_string(value));
            }
            break;
        case json_type_object:
            if (ce->type != TYPE_JSON) {
                sgxlkl_warn("Unexpected value for configuration key %s. JSON object expected.\n", key);
                goto end;
            } else {
                ce->val_char = getenv_str(ce->env_key, json_object_to_json_string(value));
            }
            break;
        default:
            sgxlkl_warn("Value of configuration key %s has unknown type.\n", key);
    }
    ce->inited = 1;

end:
    return 0;
}

int parse_sgxlkl_config(char *path, char **err) {
    return parse_json_from_file(path, parse_sgxlkl_config_entry, NULL, err);
}

int parse_sgxlkl_config_from_str(char *str, char **err) {
    return parse_json_from_str(str, parse_sgxlkl_config_entry, NULL, err);
}

int sgxlkl_configured(int opt) {
    assert(opt < sizeof(sgxlkl_config));

    if (sgxlkl_config[opt].inited)
        return 1;

    return getenv(sgxlkl_config[opt].env_key) != NULL;
}

int sgxlkl_config_bool(int opt_key) {
    assert(opt_key < sizeof(sgxlkl_config));
    assert(sgxlkl_config[opt_key].type == TYPE_BOOL);

    struct sgxlkl_config_elem *opt = &sgxlkl_config[opt_key];
    if (opt->inited)
        return opt->val_bool;

    opt->val_bool = getenv_bool(opt->env_key, opt->def_bool);
    opt->inited = 1;
    return opt->val_bool;
}

uint64_t sgxlkl_config_uint64(int opt_key) {
    assert(opt_key < sizeof(sgxlkl_config));
    assert(sgxlkl_config[opt_key].type == TYPE_UINT);

    struct sgxlkl_config_elem *opt = &sgxlkl_config[opt_key];
    if (opt->inited)
        return opt->val_uint;

    opt->val_uint = getenv_uint64(opt->env_key, opt->def_uint.val, opt->def_uint.max);
    opt->inited = 1;
    return opt->val_uint;
}

char *sgxlkl_config_str(int opt_key) {
    assert(opt_key < sizeof(sgxlkl_config));
    assert(sgxlkl_config[opt_key].type == TYPE_CHAR || sgxlkl_config[opt_key].type == TYPE_JSON);

    struct sgxlkl_config_elem *opt = &sgxlkl_config[opt_key];
    if (opt->inited)
        return opt->val_char;

    opt->val_char = getenv_str(opt->env_key, opt->def_char);
    opt->inited = 1;
    return opt->val_char;
}
