#include <assert.h>
#include <limits.h>
#include <string.h>

#include "host/sgxlkl_params.h"
#include "host/sgxlkl_util.h"
#include "shared/env.h"
#include "shared/json_util.h"
#include "shared/sgxlkl_enclave_config.h"

#define TYPE_CHAR 0
#define TYPE_UINT 1
#define TYPE_BOOL 2
#define TYPE_JSON 3

struct sgxlkl_config_uint_def
{
    uint64_t val;
    uint64_t max;
};

struct sgxlkl_config_elem
{
    char* env_key;
    char* json_key;
    int type;
    union {
        char* def_char;
        struct sgxlkl_config_uint_def def_uint;
        int def_bool;
    };
    int configured;
    int inited;
    union {
        uint64_t val_uint;
        char* val_char;
        int val_bool;
    };
};

#define DEFAULT_SGXLKL_VERBOSE 0
#define DEFAULT_SGXLKL_CWD "/"
#define DEFAULT_SGXLKL_GW4 "10.0.1.254"
/* The default heap size will only be used if no heap size is specified and
 * either we are in simulation mode, or we are in HW mode and a key is provided
 * via SGXLKL_KEY.
 */
#define DEFAULT_SGXLKL_OE_HEAP_PAGE_COUNT 8192 /* 8192 * 4K = 32MB */
#define DEFAULT_SGXLKL_HEAP_SIZE 200 * 1024 * 1024
#define DEFAULT_SGXLKL_HOSTNAME "lkl"
#define DEFAULT_SGXLKL_IP4 "10.0.1.1"
#define DEFAULT_SGXLKL_MASK4 "24"
#define DEFAULT_SGXLKL_MAX_USER_THREADS 256
#define DEFAULT_SGXLKL_ESLEEP 16000
#define DEFAULT_SGXLKL_ETHREADS 1
#define DEFAULT_SGXLKL_ESPINS 500
#define DEFAULT_SGXLKL_STACK_SIZE 512 * 1024
#define DEFAULT_SGXLKL_SWIOTLB 1
#define DEFAULT_SGXLKL_TAP "sgxlkl_tap0"
#define DEFAULT_SGXLKL_WG_IP "10.0.2.1"
#define DEFAULT_SGXLKL_WG_PORT 56002
#define DEFAULT_SGXLKL_KERNEL_CMD "mem=32M"
#define DEFAULT_SGXLKL_HOSTNET false
#define DEFAULT_SGXLKL_TAP_MTU 0

// clang-format off
static struct sgxlkl_config_elem sgxlkl_config[] = {
    {}, /* 0 */
    {"SGXLKL_CMDLINE", "cmdline", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_KERNEL_CMD}, 0}, /* 1 */ /* set LKL mem to 32MB (default is 64MB) */
    {"SGXLKL_CWD", "cwd", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_CWD}, 0}, /* 2 */
    {"SGXLKL_DEBUGMOUNT", "debugmount", TYPE_CHAR, {.def_char = NULL}, 0}, /* 3 */
    {"SGXLKL_ESPINS", "espins", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_ESPINS, ULONG_MAX}}, 0}, /* 4 */
    {"SGXLKL_ESLEEP", "esleep", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_ESLEEP, ULONG_MAX}}, 0}, /* 5 */
    {"SGXLKL_ETHREADS", "ethreads", TYPE_UINT, {.def_uint = {1, MAX_SGXLKL_ETHREADS}}, 0}, /* 6 */
    {"SGXLKL_ETHREADS_AFFINITY", "ethreads_affinity", TYPE_CHAR, {.def_char = NULL}, 0}, /* 7 */
    {}, /* 8 */
    {}, /* 9 */
    {"SGXLKL_GW4", "gw4", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_GW4}, 0}, /* 10 */
    {"SGXLKL_HD", "hd", TYPE_CHAR, {.def_char = NULL}, 0}, /* 11 */
    {"SGXLKL_HD_KEY", "hd_key", TYPE_CHAR, {.def_char = NULL}, 0}, /* 12 */
    {"SGXLKL_HD_RO", "hd_readonly", TYPE_BOOL, {.def_bool = 0}, 0}, /* 13 */
    {"SGXLKL_HDS", "hds", TYPE_CHAR, {.def_char = ""}, 0}, /* 14 */
    {"SGXLKL_HD_VERITY", "hd_verity", TYPE_CHAR, {.def_char = NULL}, 0}, /* 15 */
    {"SGXLKL_HD_VERITY_OFFSET", "hd_verity_offset", TYPE_CHAR, {.def_char = NULL}, 0}, /* 16 */ /* TODO: Change to uint64 */
    {}, /* 17 */
    {"SGXLKL_HOSTNAME", "hostname", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_HOSTNAME}, 0}, /* 18 */
    {"SGXLKL_HOSTNET", "hostnet", TYPE_BOOL, {.def_bool = 0}, 0}, /* 19 */
    {"SGXLKL_IP4", "ip4", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_IP4}, 0}, /* 20 */
    {"SGXLKL_KERNEL_VERBOSE", "kernel_verbose", TYPE_BOOL, {.def_bool = 0}, 0}, /* 21 */
    {}, /* 22 */
    {"SGXLKL_MASK4", "mask4", TYPE_UINT, {.def_char = DEFAULT_SGXLKL_MASK4}, 0}, /* 23 */
    {"SGXLKL_MAX_USER_THREADS", "max_user_threads", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_MAX_USER_THREADS, MAX_SGXLKL_MAX_USER_THREADS}}, 0}, /* 24 */
    {"SGXLKL_MMAP_FILES", "mmap_files", TYPE_CHAR, {.def_char = "None"}, 0}, /* 25 */
    {}, /* 26 */
    {"SGXLKL_PRINT_APP_RUNTIME", "print_app_runtime", TYPE_BOOL, {.def_bool = 0}, 0}, /* 27 */
    {}, /* 28 */
    {}, /* 29 */
    {}, /* 30 */
    {}, /* 31 */
    {"SGXLKL_SHMEM_FILE", "shmem_file", TYPE_CHAR, {.def_char = NULL}, 0}, /* 32 */
    {"SGXLKL_SHMEM_SIZE", "shmem_size", TYPE_UINT, {.def_uint = {0, 1024 * 1024 * 1024}}, 0}, /* 33 */
    {}, /* 34 */
    {}, /* 35 */
    {}, /* 36 */
    {"SGXLKL_STACK_SIZE", "stack_size", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_STACK_SIZE, ULONG_MAX}}, 0}, /* 37 */
    {}, /* 38 */
    {}, /* 39 */
    {"SGXLKL_SYSCTL", "sysctl", TYPE_CHAR, {.def_char = NULL}, 0}, /* 40 */
    {"SGXLKL_TAP", "tap", TYPE_CHAR, {.def_char = NULL}, 0}, /* 41 */
    {"SGXLKL_TAP_MTU", "tap_mtu", TYPE_UINT, {.def_uint = {0, INT_MAX}}, 0}, /* 42 */
    {"SGXLKL_TAP_OFFLOAD", "tap_offload", TYPE_BOOL, {.def_bool = 0}, 0}, /* 43 */
    {"SGXLKL_TRACE_HOST_SYSCALL", "trace_host_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 44 */
    {"SGXLKL_TRACE_INTERNAL_SYSCALL", "trace_internal_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 45 */
    {"SGXLKL_TRACE_LKL_SYSCALL", "trace_lkl_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 46 */
    {"SGXLKL_TRACE_IGNORED_SYSCALL", "trace_ignored_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 47 */
    {"SGXLKL_TRACE_UNSUPPORTED_SYSCALL", "trace_unsupported_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 48 */
    {"SGXLKL_TRACE_REDIRECT_SYSCALL", "trace_redirect_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 49 */
    {"SGXLKL_TRACE_MMAP", "trace_mmap", TYPE_BOOL, {.def_bool = 0}, 0}, /* 50 */
    {"SGXLKL_TRACE_SYSCALL", "trace_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 51 */
    {"SGXLKL_TRACE_THREAD", "trace_thread", TYPE_BOOL, {.def_bool = 0}, 0}, /* 52 */
    {"SGXLKL_VERBOSE", "verbose", TYPE_BOOL, {.def_bool = 0}, 0}, /* 53 */
    {}, /* 54 */
    {}, /* 55 */
    {"SGXLKL_WG_IP", "wg_ip", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_WG_IP}, 0}, /* 56 */
    {"SGXLKL_WG_PORT", "wg_port", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_WG_PORT, USHRT_MAX}}, 0}, /* 57 */
    {"SGXLKL_WG_KEY", "wg_key", TYPE_CHAR, {.def_char = NULL}, 0}, /* 58 */
    {"SGXLKL_WG_PEERS", "wg_peers", TYPE_CHAR, {.def_char = ""}, 0}, /* 59 */
    {"SGXLKL_OE_HEAP_PAGE_COUNT", "oe_heap_page_count", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_OE_HEAP_PAGE_COUNT, ULONG_MAX}}, 0}, /* 60 */
    {}, /* 61 */
    {}, /* 62 */
    {}, /* 63 */
    {}, /* 64 */
    {"SGXLKL_ENABLE_SWIOTLB", "swiotlb", TYPE_BOOL, {.def_bool = DEFAULT_SGXLKL_SWIOTLB}, 0}, /* 65 */
    {"SGXLKL_HD_OVERLAY", "hd_overlay", TYPE_BOOL, {.def_bool = false}, 0}, /* 66 */
    {"SGXLKL_HOST_IMPORT_ENV", "host_import_envp", TYPE_CHAR, {.def_char = NULL}, 0}, /* 67 */
};
// clang-format off

static inline struct sgxlkl_config_elem* config_elem_by_key(const char* key)
{
    for (int i = 0; i < sizeof(sgxlkl_config) / sizeof(sgxlkl_config[0]); i++)
    {
        if (sgxlkl_config[i].json_key &&
            !strcmp(sgxlkl_config[i].json_key, key))
            return &sgxlkl_config[i];
    }
    return NULL;
}

static int parse_sgxlkl_config_entry(
    const char* key,
    struct json_object* value,
    void* arg)
{
    struct sgxlkl_config_elem* ce = config_elem_by_key(key);
    if (!ce)
    {
        sgxlkl_host_warn("Unknown configuration entry: %s\n", key);
        goto end;
    }

    int json_val_type = json_object_get_type(value);
    switch (json_val_type)
    {
        case json_type_boolean:
            if (ce->type != TYPE_BOOL)
            {
                sgxlkl_host_warn(
                    "Unexpected value for configuration key %s. Boolean "
                    "expected.\n",
                    key);
                goto end;
            }
            else
            {
                ce->val_bool =
                    getenv_bool(ce->env_key, json_object_get_boolean(value));
            }
            break;
        case json_type_int:
            if (ce->type != TYPE_UINT)
            {
                sgxlkl_host_warn(
                    "Unexpected value for configuration key %s. Integer "
                    "expected.\n",
                    key);
                goto end;
            }
            else
            {
                ce->val_uint = getenv_uint64(
                    ce->env_key,
                    json_object_get_int64(value),
                    ce->def_uint.max);
            }
            break;
        case json_type_string:
            // Size string, e.g. "12k"?
            if (ce->type == TYPE_UINT)
            {
                uint64_t val = size_str_to_uint64(
                    json_object_get_string(value),
                    ce->def_uint.val,
                    ce->def_uint.max);
                ce->val_uint =
                    getenv_uint64(ce->env_key, val, ce->def_uint.max);
            }
            else if (ce->type != TYPE_CHAR)
            {
                sgxlkl_host_warn(
                    "Unexpected value for configuration key %s. String "
                    "expected.\n",
                    key);
                goto end;
            }
            else
            {
                ce->val_char =
                    getenv_str(ce->env_key, json_object_get_string(value));
            }
            break;
        case json_type_object:
            if (ce->type != TYPE_JSON)
            {
                sgxlkl_host_warn(
                    "Unexpected value for configuration key %s. JSON object "
                    "expected.\n",
                    key);
                goto end;
            }
            else
            {
                ce->val_char =
                    getenv_str(ce->env_key, json_object_to_json_string(value));
            }
            break;
        default:
            sgxlkl_host_warn(
                "Value of configuration key %s has unknown type.\n", key);
    }
    ce->inited = 1;
    ce->configured = 1;

end:
    return 0;
}

int parse_sgxlkl_config(const char* path, char** err)
{
    return parse_json_from_file(path, parse_sgxlkl_config_entry, NULL, err);
}

int parse_sgxlkl_config_from_str(char* str, char** err)
{
    return parse_json_from_str(str, parse_sgxlkl_config_entry, NULL, err);
}

int sgxlkl_configured(int opt)
{
    assert(opt < sizeof(sgxlkl_config));

    if (sgxlkl_config[opt].configured)
        return 1;

    return getenv(sgxlkl_config[opt].env_key) != NULL;
}

int sgxlkl_config_bool(int opt_key)
{
    assert(opt_key < sizeof(sgxlkl_config));
    assert(sgxlkl_config[opt_key].type == TYPE_BOOL);

    struct sgxlkl_config_elem* opt = &sgxlkl_config[opt_key];
    if (opt->inited)
        return opt->val_bool;

    opt->val_bool = getenv_bool(opt->env_key, opt->def_bool);
    opt->inited = 1;
    return opt->val_bool;
}

uint64_t sgxlkl_config_uint64(int opt_key)
{
    assert(opt_key < sizeof(sgxlkl_config));
    assert(sgxlkl_config[opt_key].type == TYPE_UINT);

    struct sgxlkl_config_elem* opt = &sgxlkl_config[opt_key];
    if (opt->inited)
        return opt->val_uint;

    opt->val_uint =
        getenv_uint64(opt->env_key, opt->def_uint.val, opt->def_uint.max);
    opt->inited = 1;
    return opt->val_uint;
}

char* sgxlkl_config_str(int opt_key)
{
    assert(opt_key < sizeof(sgxlkl_config));
    assert(
        sgxlkl_config[opt_key].type == TYPE_CHAR ||
        sgxlkl_config[opt_key].type == TYPE_JSON);

    struct sgxlkl_config_elem* opt = &sgxlkl_config[opt_key];
    if (opt->inited)
        return opt->val_char;

    opt->val_char = getenv_str(opt->env_key, opt->def_char);
    opt->inited = 1;
    return opt->val_char;
}
