#ifdef SGXLKL_ENCLAVE
#include <enclave/enclave_util.h>
#include <shared/oe_compat.h>
#define FAIL sgxlkl_fail
#define WARN sgxlkl_warn
#else
#include <host/sgxlkl_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FAIL sgxlkl_host_fail
#define WARN sgxlkl_host_warn
#endif

#include <enclave/enclave_util.h>
#include <json.h>
#include <shared/env.h>
#include <shared/sgxlkl_enclave_config.h>
#include <shared/string_list.h>

#define CHECKMEM(C) \
    if (!C)         \
        FAIL("out of memory\n");

// Duplicate a string (including NULL)
static int strdupz(char** to, const char* from)
{
    if (!to)
        return 1;
    else if (!from)
    {
        *to = NULL;
        return 0;
    }
    else
    {
        size_t l = strlen(from);
        *to = malloc(l + 1);
        CHECKMEM(*to);
        memcpy(*to, from, l + 1);
    }
    return 0;
}

typedef struct json_callback_data
{
    sgxlkl_enclave_config_t* config;
    unsigned long index;
    string_list_t* seen;
    bool enforce_format;
} json_callback_data_t;

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

    char* r = NULL;
    strdupz(&r, tmp);
    return r;
}

#define SEEN(X) data->seen = string_list_add(data->seen, make_path(parser));

#define CHECK(T)                                    \
    if (type != T)                                  \
    {                                               \
        FAIL(                                       \
            "Expected type %d for '%s' (is %d).\n", \
            (int)T,                                 \
            (int)type,                              \
            make_path(parser));                     \
        return JSON_BAD_PARAMETER;                  \
    }

#define CHECK2(T1, T2)                            \
    if (type != T1 && type != T2)                 \
    {                                             \
        FAIL(                                     \
            "Expected type %d or %d for '%s'.\n", \
            (int)T1,                              \
            (int)T2,                              \
            make_path(parser));                   \
        return JSON_BAD_PARAMETER;                \
    }

#define MATCH(PATH) json_match(parser, PATH) == JSON_OK

#define JPATH(PATH, CODE) \
    if (MATCH(PATH))      \
    {                     \
        SEEN(parser);     \
        CODE;             \
        return JSON_OK;   \
    }

#define JPATHT(PATH, TYPE, CODE) \
    if (MATCH(PATH))             \
    {                            \
        SEEN(parser);            \
        CHECK(TYPE);             \
        CODE;                    \
        return JSON_OK;          \
    }

#define JPATH2T(PATH, TYPE1, TYPE2, CODE) \
    if (MATCH(PATH))                      \
    {                                     \
        SEEN(parser);                     \
        CHECK2(TYPE1, TYPE2);             \
        CODE;                             \
        return JSON_OK;                   \
    }

#define JSTRING(PATH, DEST)                           \
    JPATH2T(PATH, JSON_TYPE_STRING, JSON_TYPE_NULL, { \
        if (strdupz(&(DEST), un ? un->string : NULL)) \
            return JSON_FAILED;                       \
    });

static json_result_t decode_safe_uint64_t(
    json_parser_t* parser,
    json_type_t type,
    const json_union_t* value,
    uint64_t* to)
{
    if (!to)
        return JSON_BAD_PARAMETER;
    if (type != JSON_TYPE_STRING)
        FAIL("invalid value type for '%s'\n", make_path(parser));
    _Static_assert(
        sizeof(unsigned long) == 8, "unexpected size of unsigned long");
    json_conversion_error = JSON_OK;
    uint64_t tmp = _strtoul(value->string, NULL, 10, false);
    if (json_conversion_error != JSON_OK)
        return json_conversion_error;
    *to = tmp;
    return JSON_OK;
}

static json_result_t decode_any_uint64_t(
    json_parser_t* parser,
    json_type_t type,
    const json_union_t* value,
    uint64_t* to)
{
    if (!to)
        return JSON_BAD_PARAMETER;
    uint64_t tmp;
    if (type == JSON_TYPE_STRING)
    {
        json_conversion_error = JSON_OK;
        tmp = _strtoul(value->string, NULL, 10, true);
        if (json_conversion_error != JSON_OK)
            return json_conversion_error;
    }
    else if (type == JSON_TYPE_INTEGER)
        tmp = value->integer;
    else if (type == JSON_TYPE_REAL)
        tmp = value->real;
    else if (type == JSON_TYPE_NULL)
        tmp = 0;
    else
        return JSON_UNKNOWN_VALUE;
    *to = tmp;
    return JSON_OK;
}

static json_result_t decode_uint64_t(
    json_parser_t* parser,
    json_type_t type,
    const json_union_t* value,
    char* path,
    uint64_t* to)
{
    if (((json_callback_data_t*)parser->callback_data)->enforce_format)
        return decode_safe_uint64_t(parser, type, value, to);
    else
        return decode_any_uint64_t(parser, type, value, to);
}

static json_result_t decode_uint32_t(
    json_parser_t* parser,
    json_type_t type,
    const json_union_t* value,
    char* path,
    uint32_t* to)
{
    uint64_t tmp = 0;
    json_result_t r = decode_uint64_t(parser, type, value, path, &tmp);
    if (r != JSON_OK)
        return r;
    if (tmp > UINT32_MAX)
        return JSON_OUT_OF_BOUNDS;
    *to = (uint32_t)tmp;
    return JSON_OK;
}

#define JHEXBUF(PATH, DEST)                                  \
    JPATH2T(PATH, JSON_TYPE_STRING, JSON_TYPE_NULL, {        \
        if (type == JSON_TYPE_NULL)                          \
            DEST = NULL;                                     \
        else                                                 \
        {                                                    \
            size_t l = strlen(un->string);                   \
            DEST##_len = l / 2;                              \
            DEST = calloc(1, DEST##_len);                    \
            CHECKMEM(DEST);                                  \
            for (size_t i = 0; i < DEST##_len; i++)          \
                DEST[i] = hex_to_int(un->string + 2 * i, 2); \
        }                                                    \
    });

#define JBOOL(PATH, DEST) \
    JPATHT(PATH, JSON_TYPE_BOOLEAN, (DEST) = un->boolean;);

#define JU64(P, D) JPATH(P, return decode_uint64_t(parser, type, un, P, &D));
#define JU32(P, D) JPATH(P, return decode_uint32_t(parser, type, un, P, &D));

#define ALLOC_ARRAY(N, A, T)                              \
    do                                                    \
    {                                                     \
        data->config->N = un->integer;                    \
        data->config->A = calloc(un->integer, sizeof(T)); \
        CHECKMEM(data->config->A);                        \
    } while (0)

static unsigned long get_array_index(json_parser_t* parser)
{
    if (parser->depth < 2)
        FAIL("invalid array index\n");
    return parser->path[parser->depth - 2].index;
}

static json_result_t json_read_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    static char* last_path = NULL;
    json_callback_data_t* data = (json_callback_data_t*)callback_data;
    size_t i = parser->path[parser->depth - 1].index;
    sgxlkl_enclave_config_t* cfg = data->config;

    switch (reason)
    {
        case JSON_REASON_NONE:
            SGXLKL_ASSERT("unreachable");
        case JSON_REASON_NAME:
            break;
        case JSON_REASON_BEGIN_OBJECT:
            if (data->enforce_format)
                last_path = make_path(parser);
            break;
        case JSON_REASON_END_OBJECT:
            break;
        case JSON_REASON_BEGIN_ARRAY:
            if (MATCH("args"))
                ALLOC_ARRAY(num_args, args, char*);
            else if (MATCH("env"))
                ALLOC_ARRAY(num_env, env, char*);
            else if (MATCH("mounts"))
                ALLOC_ARRAY(num_mounts, mounts, sgxlkl_enclave_mount_config_t);
            else if (MATCH("host_import_env"))
                ALLOC_ARRAY(num_host_import_env, host_import_env, char*);
            else if (MATCH("wg.peers"))
                ALLOC_ARRAY(
                    wg.num_peers, wg.peers, sgxlkl_enclave_wg_peer_config_t);
            else if (!(MATCH("clock_res")))
                FAIL("unknown json array '%s'\n", make_path(parser));
            break;
        case JSON_REASON_END_ARRAY:
            if (data->enforce_format)
                last_path = make_path(parser);
            break;
        case JSON_REASON_VALUE:
        {
            if (data->enforce_format)
            {
                char* cur_path = make_path(parser);
                if (last_path)
                {
                    if (strcmp(last_path, cur_path) > 0)
                        FAIL("unsorted json: %s >= %s\n", last_path, cur_path);
                    free(last_path);
                }
                last_path = cur_path;
            }

            JPATHT("format_version", JSON_TYPE_STRING, {
                uint64_t format_version =
                    _strtoul(un->string, NULL, 10, !data->enforce_format);
                if (format_version != SGXLKL_ENCLAVE_CONFIG_VERSION)
                    FAIL(
                        "invalid enclave config format version %lu\n",
                        un->integer);
            });

            JU64("stacksize", cfg->stacksize);
            JPATHT("mmap_files", JSON_TYPE_STRING, {
                cfg->mmap_files =
                    string_to_sgxlkl_enclave_mmap_files_t(un->string);
            });
            JU64("oe_heap_pagecount", cfg->oe_heap_pagecount);
            JSTRING("net_ip4", cfg->net_ip4);
            JSTRING("net_gw4", cfg->net_gw4);
            JSTRING("net_mask4", cfg->net_mask4);
            JSTRING("hostname", cfg->hostname);
            JU32("tap_mtu", cfg->tap_mtu);
            JBOOL("hostnet", cfg->hostnet);

            JSTRING("wg.ip", cfg->wg.ip);
            JU32("wg.listen_port", cfg->wg.listen_port);
            JSTRING("wg.key", cfg->wg.key);
            JSTRING("wg.peers.key", cfg->wg.peers[i].key);
            JSTRING("wg.peers.allowed_ips", cfg->wg.peers[i].allowed_ips);
            JSTRING("wg.peers.endpoint", cfg->wg.peers[i].endpoint);

            JU64("max_user_threads", cfg->max_user_threads);
            JU64("ethreads", cfg->ethreads);
            JU64("espins", cfg->espins);
            JU64("esleep", cfg->esleep);

            JPATHT("clock_res.resolution", JSON_TYPE_STRING, {
                if (strlen(un->string) != 16)
                    FAIL("invalid length of value for clock_res item");
                i = get_array_index(parser);
                if (i >= 8)
                    FAIL("too many values for clock_res");
                memcpy(&cfg->clock_res[i].resolution, un->string, 17);
            });

            JPATHT("mode", JSON_TYPE_STRING, {
                cfg->mode = string_to_sgxlkl_enclave_mode_t(un->string);
            });
            JBOOL("fsgsbase", cfg->fsgsbase);
            JBOOL("verbose", cfg->verbose);
            JBOOL("kernel_verbose", cfg->kernel_verbose);
            JSTRING("kernel_cmd", cfg->kernel_cmd);
            JSTRING("sysctl", cfg->sysctl);
            JBOOL("swiotlb", cfg->swiotlb);

            JSTRING("cwd", cfg->cwd);
            JPATHT("args", JSON_TYPE_STRING, {
                strdupz(&cfg->args[i], un->string);
            });
            JPATHT("env", JSON_TYPE_STRING, {
                strdupz(&cfg->env[i], un->string);
            });
            JPATHT("host_import_env", JSON_TYPE_STRING, {
                strdupz(&cfg->host_import_env[i], un->string);
            });

            JPATHT("exit_status", JSON_TYPE_STRING, {
                cfg->exit_status =
                    string_to_sgxlkl_exit_status_mode_t(un->string);
            });

            JHEXBUF("root.key", data->config->root.key);
            JSTRING("root.key_id", data->config->root.key_id);
            JBOOL("root.readonly", data->config->root.readonly);
            JSTRING("root.roothash", data->config->root.roothash);
            JU64("root.roothash_offset", data->config->root.roothash_offset);
            JBOOL("root.overlay", data->config->root.overlay);

#define MOUNT() (&(cfg->mounts[get_array_index(parser)]))
            JBOOL("mounts.create", MOUNT()->create);
            JBOOL("mounts.fresh_key", MOUNT()->fresh_key);
            JHEXBUF("mounts.key", MOUNT()->key);
            JSTRING("mounts.key_id", MOUNT()->key_id);
            if (MATCH("mounts.destination"))
            {
                SEEN(parser);
                size_t len = strlen(un->string);
                if (len > SGXLKL_DISK_MNT_MAX_PATH_LEN)
                    FAIL("'destination' of disk %d too long\n", i);
                memcpy(MOUNT()->destination, un->string, len + 1);
                return JSON_OK;
            }
            JBOOL("mounts.readonly", MOUNT()->readonly);
            JSTRING("mounts.roothash", MOUNT()->roothash);
            JU64("mounts.roothash_offset", MOUNT()->roothash_offset);
            JU64("mounts.size", MOUNT()->size);

            sgxlkl_image_sizes_config_t* sizes = &cfg->image_sizes;
            JU64("image_sizes.num_heap_pages", sizes->num_heap_pages);
            JU64("image_sizes.num_stack_pages", sizes->num_stack_pages);

            FAIL(
                "Invalid unknown json element '%s'; refusing to run with this "
                "enclave config.\n",
                make_path(parser));
        }
    }

    return JSON_OK;
}

void check_config(const sgxlkl_enclave_config_t* cfg)
{
#define CC(C, M) \
    if (C)       \
        FAIL("rejecting enclave configuration: " M "\n");

    CC(cfg->args == NULL, "missing args");
    CC(cfg->num_args == 0, "num_args == 0");
    CC(cfg->ethreads > MAX_SGXLKL_ETHREADS, "too many ethreads");
    CC(cfg->max_user_threads > MAX_SGXLKL_MAX_USER_THREADS,
       "max_user_threads too large");

    // These are cast to (signed) int later.
    CC(cfg->tap_mtu > INT32_MAX, "tap_mtu out of range");
    CC(cfg->num_args > INT32_MAX, "size of args out of range");
    CC(cfg->num_env > INT32_MAX, "size of env out of range");
    CC(cfg->num_host_import_env > INT32_MAX,
       "size of host_import_env out of range");
}

void check_required_elements(string_list_t* seen)
{
    const char* required[] = {"args"};
    const size_t num_required = sizeof(required) / sizeof(char*);
    for (size_t i = 0; i < num_required; i++)
    {
        const char* r = required[i];
        if (!string_list_contains(seen, r))
            FAIL("config does not contain required element '%s'\n", r);
    }
}

void sgxlkl_read_enclave_config(
    const char* from,
    sgxlkl_enclave_config_t* to,
    bool enforce_format)
{
    // Catch modifications to sgxlkl_enclave_config_t early. If this fails,
    // the code above/below needs adjusting for the added/removed settings.
    _Static_assert(
        sizeof(sgxlkl_enclave_config_t) == 456,
        "sgxlkl_enclave_config_t size has changed");

    if (!from)
        FAIL("No config to read\n");

    if (!to)
        FAIL("No config to write to\n");

    *to = sgxlkl_default_enclave_config;

    json_parser_t parser;
    json_parser_options_t options;
    options.allow_whitespace = !enforce_format;
    json_result_t r = JSON_UNEXPECTED;
    json_callback_data_t callback_data = {.config = to,
                                          .index = 0,
                                          .seen = NULL,
                                          .enforce_format = enforce_format};

    // parser destroys `from`, so we copy it first.
    size_t json_len = strlen(from);
    char* json_copy = malloc(sizeof(char) * (json_len + 1));
    memcpy(json_copy, from, json_len);

    json_allocator_t allocator = {.ja_malloc = malloc, .ja_free = free};

    if ((r = json_parser_init(
             &parser,
             json_copy,
             strlen(from),
             json_read_callback,
             &callback_data,
             &allocator,
             &options)) != JSON_OK)
        FAIL("json_parser_init() failed: %d\n", r);

    if ((r = json_parser_parse(&parser)) != JSON_OK)
        FAIL("json_parser_parse() failed: %d\n", r);

    if (parser.depth != 0)
        FAIL("unterminated json objects\n");

    free(json_copy);

    if (enforce_format)
        check_required_elements(callback_data.seen);
    check_config(to);
    string_list_free(callback_data.seen);
}

#define NONDEFAULT_FREE(X)              \
    if (config->X != default_config->X) \
        free(config->X);

void sgxlkl_free_enclave_config(sgxlkl_enclave_config_t* config)
{
    const sgxlkl_enclave_config_t* default_config =
        &sgxlkl_default_enclave_config;

    NONDEFAULT_FREE(net_ip4);
    NONDEFAULT_FREE(net_gw4);

    NONDEFAULT_FREE(wg.ip);
    for (size_t i = 0; i < config->wg.num_peers; i++)
    {
        free(config->wg.peers[i].key);
        free(config->wg.peers[i].allowed_ips);
        free(config->wg.peers[i].endpoint);
    }
    NONDEFAULT_FREE(wg.peers);

    NONDEFAULT_FREE(kernel_cmd);
    NONDEFAULT_FREE(sysctl);

    for (size_t i = 0; i < config->num_args; i++)
        free(config->args[i]);
    NONDEFAULT_FREE(args);

    for (size_t i = 0; i < config->num_env; i++)
        free(config->env[i]);
    NONDEFAULT_FREE(env);

    for (size_t i = 0; i < config->num_host_import_env; i++)
        free(config->host_import_env[i]);
    NONDEFAULT_FREE(host_import_env);

    NONDEFAULT_FREE(root.key);
    NONDEFAULT_FREE(root.key_id);
    NONDEFAULT_FREE(root.roothash);

    for (size_t i = 0; i < config->num_mounts; i++)
    {
        free(config->mounts[i].key);
        free(config->mounts[i].key_id);
        free(config->mounts[i].roothash);
    }
    NONDEFAULT_FREE(mounts);
    free(config);
}

bool is_encrypted(sgxlkl_enclave_mount_config_t* cfg)
{
    return cfg->key || cfg->key_id || cfg->fresh_key;
}