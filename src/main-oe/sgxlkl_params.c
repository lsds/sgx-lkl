#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include "host/sgxlkl_params.h"
#include "host/sgxlkl_util.h"
#include "shared/env.h"
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

typedef struct json_callback_data
{
} json_callback_data_t;

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
    {"SGXLKL_CMDLINE", "cmdline", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_KERNEL_CMD}, 0}, /* 1 */
    {"SGXLKL_CWD", "cwd", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_CWD}, 0}, /* 2 */
    {"SGXLKL_DEBUGMOUNT", "debugmount", TYPE_CHAR, {.def_char = NULL}, 0}, /* 3 */
    {"SGXLKL_ESPINS", "espins", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_ESPINS, ULONG_MAX}}, 0}, /* 4 */
    {"SGXLKL_ESLEEP", "esleep", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_ESLEEP, ULONG_MAX}}, 0}, /* 5 */
    {"SGXLKL_ETHREADS", "ethreads", TYPE_UINT, {.def_uint = {1, MAX_SGXLKL_ETHREADS}}, 0}, /* 6 */
    {"SGXLKL_ETHREADS_AFFINITY", "ethreads_affinity", TYPE_CHAR, {.def_char = NULL}, 0}, /* 7 */
    {"SGXLKL_GW4", "gw4", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_GW4}, 0}, /* 8 */
    {"SGXLKL_HD", "hd", TYPE_CHAR, {.def_char = NULL}, 0}, /* 9 */
    {"SGXLKL_HD_KEY", "hd_key", TYPE_CHAR, {.def_char = NULL}, 0}, /* 10 */
    {"SGXLKL_HD_RO", "hd_readonly", TYPE_BOOL, {.def_bool = 0}, 0}, /* 11 */
    {"SGXLKL_HDS", "hds", TYPE_CHAR, {.def_char = ""}, 0}, /* 12 */
    {"SGXLKL_HD_VERITY", "hd_verity", TYPE_CHAR, {.def_char = NULL}, 0}, /* 13 */
    {"SGXLKL_HD_VERITY_OFFSET", "hd_verity_offset", TYPE_CHAR, {.def_char = NULL}, 0}, /* 14 */ /* TODO: Change to uint64 */
    {"SGXLKL_HOSTNAME", "hostname", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_HOSTNAME}, 0}, /* 15 */
    {"SGXLKL_HOSTNET", "hostnet", TYPE_BOOL, {.def_bool = 0}, 0}, /* 16 */
    {"SGXLKL_IP4", "ip4", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_IP4}, 0}, /* 17 */
    {"SGXLKL_KERNEL_VERBOSE", "kernel_verbose", TYPE_BOOL, {.def_bool = 0}, 0}, /* 18 */
    {"SGXLKL_MASK4", "mask4", TYPE_UINT, {.def_char = DEFAULT_SGXLKL_MASK4}, 0}, /* 19 */
    {"SGXLKL_MAX_USER_THREADS", "max_user_threads", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_MAX_USER_THREADS, MAX_SGXLKL_MAX_USER_THREADS}}, 0}, /* 20 */
    {"SGXLKL_MMAP_FILES", "mmap_files", TYPE_CHAR, {.def_char = "None"}, 0}, /* 21 */
    {"SGXLKL_PRINT_APP_RUNTIME", "print_app_runtime", TYPE_BOOL, {.def_bool = 0}, 0}, /* 22 */
    {"SGXLKL_STACK_SIZE", "stack_size", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_STACK_SIZE, ULONG_MAX}}, 0}, /* 23 */
    {"SGXLKL_SYSCTL", "sysctl", TYPE_CHAR, {.def_char = NULL}, 0}, /* 24 */
    {"SGXLKL_TAP", "tap", TYPE_CHAR, {.def_char = NULL}, 0}, /* 25 */
    {"SGXLKL_TAP_MTU", "tap_mtu", TYPE_UINT, {.def_uint = {0, INT_MAX}}, 0}, /* 26 */
    {"SGXLKL_TAP_OFFLOAD", "tap_offload", TYPE_BOOL, {.def_bool = 0}, 0}, /* 27 */
    {"SGXLKL_TRACE_HOST_SYSCALL", "trace_host_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 28 */
    {"SGXLKL_TRACE_INTERNAL_SYSCALL", "trace_internal_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 29 */
    {"SGXLKL_TRACE_LKL_SYSCALL", "trace_lkl_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 30 */
    {"SGXLKL_TRACE_IGNORED_SYSCALL", "trace_ignored_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 31 */
    {"SGXLKL_TRACE_UNSUPPORTED_SYSCALL", "trace_unsupported_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 32 */
    {"SGXLKL_TRACE_REDIRECT_SYSCALL", "trace_redirect_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 33 */
    {"SGXLKL_TRACE_MMAP", "trace_mmap", TYPE_BOOL, {.def_bool = 0}, 0}, /* 34 */
    {"SGXLKL_TRACE_SYSCALL", "trace_syscall", TYPE_BOOL, {.def_bool = 0}, 0}, /* 35 */
    {"SGXLKL_TRACE_THREAD", "trace_thread", TYPE_BOOL, {.def_bool = 0}, 0}, /* 36 */
    {"SGXLKL_VERBOSE", "verbose", TYPE_BOOL, {.def_bool = 0}, 0}, /* 37 */
    {"SGXLKL_WG_IP", "wg_ip", TYPE_CHAR, {.def_char = DEFAULT_SGXLKL_WG_IP}, 0}, /* 38 */
    {"SGXLKL_WG_PORT", "wg_port", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_WG_PORT, USHRT_MAX}}, 0}, /* 39 */
    {"SGXLKL_WG_KEY", "wg_key", TYPE_CHAR, {.def_char = NULL}, 0}, /* 40 */
    {"SGXLKL_WG_PEERS", "wg_peers", TYPE_CHAR, {.def_char = ""}, 0}, /* 41 */
    {"SGXLKL_OE_HEAP_PAGE_COUNT", "oe_heap_page_count", TYPE_UINT, {.def_uint = {DEFAULT_SGXLKL_OE_HEAP_PAGE_COUNT, ULONG_MAX}}, 0}, /* 42 */
    {"SGXLKL_ENABLE_SWIOTLB", "swiotlb", TYPE_BOOL, {.def_bool = DEFAULT_SGXLKL_SWIOTLB}, 0}, /* 43 */
    {"SGXLKL_HD_OVERLAY", "hd_overlay", TYPE_BOOL, {.def_bool = false}, 0}, /* 44 */
    {"SGXLKL_HOST_IMPORT_ENV", "host_import_env", TYPE_CHAR, {.def_char = NULL}, 0}, /* 45 */
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

static char* make_path(json_parser_t* parser)
{
    static char tmp[1024] = "";

    if (parser->depth > 0)
    {
        char* p = (char*)tmp;
        size_t len = strlen(parser->path[0].name);
        memcpy(p, parser->path[0].name, len);
        p += len;
        *p = '\0';
        for (size_t i = 1; i < parser->depth; i++)
        {
            len = strlen(parser->path[i].name);
            *(p++) = '.';
            memcpy(p, parser->path[i].name, len);
            p += len;
            *p = '\0';
        }
    }

    return strdup(tmp);
}


static json_result_t parse_sgxlkl_config_entry(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    switch (reason)
    {
        case JSON_REASON_NONE:
            assert("unreachable");
        case JSON_REASON_NAME: break;
        case JSON_REASON_BEGIN_OBJECT: break;
        case JSON_REASON_END_OBJECT: break;
        case JSON_REASON_BEGIN_ARRAY: break;
        case JSON_REASON_END_ARRAY: break;
        case JSON_REASON_VALUE: {
            char *path = make_path(parser);
            struct sgxlkl_config_elem* ce = config_elem_by_key(path);

            if (!ce)
            {
                sgxlkl_host_warn("Unknown configuration entry: %s\n", path);
                free(path);
                return JSON_OK;
            }

            ce->inited = 1;
            ce->configured = 1;

            switch (type) {
              case JSON_TYPE_BOOLEAN:
                if (ce->type == TYPE_BOOL)  {
                  sgxlkl_host_warn(
                      "Unexpected value for configuration %s. Boolean "
                      "expected.\n",
                      path);
                }
                else
                  ce->val_bool = getenv_bool(ce->env_key, un->boolean);

                break;
              case JSON_TYPE_INTEGER:
                  if (ce->type == TYPE_UINT)
                  {
                      sgxlkl_host_warn(
                          "Unexpected value for configuration %s. Integer "
                          "expected.\n",
                          path);
                  }
                  else
                  {
                      ce->val_uint = getenv_uint64(
                          ce->env_key,
                          un->integer,
                          ce->def_uint.max);
                  }
                  break;
              case JSON_TYPE_STRING:
                  if (ce->type == TYPE_UINT)
                  {
                      uint64_t val = size_str_to_uint64(
                          un->string,
                          ce->def_uint.val,
                          ce->def_uint.max);
                      ce->val_uint =
                          getenv_uint64(ce->env_key, val, ce->def_uint.max);
                  }
                  else if (ce->type != TYPE_CHAR)
                  {
                      sgxlkl_host_warn(
                          "Unexpected value for configuration %s. String "
                          "expected.\n",
                          path);
                  }
                  else
                  {
                      ce->val_char =
                          getenv_str(ce->env_key, un->string);
                  }
                  break;
              default:
                  sgxlkl_host_warn(
                      "Value of configuration %s has unknown type.\n", path);
                break;
            }
        }
        default:
          sgxlkl_host_warn("Unknown json reason %d.\n", reason);
        break;
    }

    return JSON_OK;
}

int sgxlkl_parse_params_from_str(char* from, char** err)
{
    json_parser_t parser;
    json_parser_options_t options;
    options.allow_whitespace = true;
    json_result_t r = JSON_UNEXPECTED;
    json_callback_data_t callback_data = {};

    // parser destroys `from`, so we copy it first.
    size_t json_len = strlen(from);
    char* json_copy = malloc(sizeof(char) * (json_len + 1));
    memcpy(json_copy, from, json_len);

    json_allocator_t allocator = {.ja_malloc = malloc, .ja_free = free};

    if ((r = json_parser_init(
             &parser,
             json_copy,
             strlen(from),
             parse_sgxlkl_config_entry,
             &callback_data,
             &allocator,
             &options)) != JSON_OK)
        sgxlkl_host_fail("json_parser_init() failed: %d\n", r);

    if ((r = json_parser_parse(&parser)) != JSON_OK)
        sgxlkl_host_fail("json_parser_parse() failed: %d\n", r);

    if (parser.depth != 0)
        sgxlkl_host_fail("unterminated json objects\n");

    free(json_copy);

    return 0;
}

int sgxlkl_parse_params_from_file(const char* path, char** err)
{
  int fd;
    if ((fd = open(path, O_RDONLY)) < 0)
    {
        if (err)
            *err = strdup(strerror(errno));
        else
            perror("Failed to open JSON file");
        return -1;
    }

    off_t len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char* buf;
    if (!(buf = (char*)malloc(len + 1)))
    {
        if (err)
            *err = strdup("Failed to allocate memory for JSON buffer");
        else
            perror("Failed to allocate memory for JSON buffer");
        return -1;
    }
    ssize_t ret;
    int off = 0;
    while ((ret = read(fd, &buf[off], len - off)) > 0)
    {
        off += ret;
    }
    buf[len] = 0;

    close(fd);

    if (ret < 0)
    {
        if (err)
            *err = strdup(strerror(errno));
        else
            perror("Failed to read from JSON file");
        free(buf);
        return -1;
    }

    int res = sgxlkl_parse_params_from_str(buf, err);
    free(buf);
    return res;
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
