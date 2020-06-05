#include <enclave/oe_compat.h>

#ifdef SGXLKL_ENCLAVE
#include <enclave/enclave_util.h>
#define FAIL sgxlkl_fail
#define INFO sgxlkl_info
// oe_strtol missing
long int strtol(const char* nptr, char** endptr, int base);
#else
#include <host/sgxlkl_util.h>
#include <stdlib.h>
#include <string.h>
#define FAIL sgxlkl_host_fail
#define INFO sgxlkl_host_info
#endif

#include <arpa/inet.h>
#include <errno.h>

#include <enclave/enclave_mem.h>
#include <shared/json.h>
#include <shared/read_enclave_config.h>
#include <shared/sgxlkl_enclave_config.h>
#include <shared/string_list.h>

// Duplicate a string
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
        if (!*to)
        {
            *to = NULL;
            return 1;
        }
        else
            memcpy(*to, from, l + 1);
    }
    return 0;
}

static int strndupz(char** to, const char* from, size_t n)
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
        *to = malloc(n + 1);
        if (!*to)
        {
            *to = NULL;
            return 1;
        }
        else
            memcpy(*to, from, n + 1);
    }
    return 0;
}

typedef struct json_callback_data
{
    sgxlkl_enclave_config_t* config;
    sgxlkl_app_config_t* app_config;
    size_t buffer_sz;
    unsigned long index;
    string_list_t* seen;
    void* array;
    size_t array_count;
    char** envp;
    size_t envc, auxc;
} json_callback_data_t;

static char* make_path(json_parser_t* parser)
{
    static char tmp[1024] = "";

    if (parser->depth > 0)
    {
        char* p = (char*)tmp;
        p += sprintf(p, "%s", parser->path[0]);
        for (size_t i = 1; i < parser->depth; i++)
            p += sprintf(p, ".%s", parser->path[i]);
    }

    char* r = NULL;
    strdupz(&r, tmp);
    return r;
}

static void show_path(json_parser_t* parser)
{
    char* tmp = make_path(parser);
    INFO("json path: %s\n", tmp);
    free(tmp);
}

#define SEEN(X) data->seen = string_list_add(data->seen, make_path(parser));

#define CHECK(T)                                    \
    if (type != T)                                  \
    {                                               \
        FAIL(                                       \
            "Expected type %d for '%s' (is %d).\n", \
            (int)T,                                 \
            (int)type,                              \
            parser->path[parser->depth - 1]);       \
        return JSON_BAD_PARAMETER;                  \
    }

#define CHECK2(T1, T2)                            \
    if (type != T1 && type != T2)                 \
    {                                             \
        FAIL(                                     \
            "Expected type %d or %d for '%s'.\n", \
            (int)T1,                              \
            (int)T2,                              \
            parser->path[parser->depth - 1]);     \
        return JSON_BAD_PARAMETER;                \
    }

#define JPATH(PATH, CODE)                        \
    if (json_match(parser, PATH, &i) == JSON_OK) \
    {                                            \
        SEEN(parser);                            \
        CODE;                                    \
        return JSON_OK;                          \
    }

#define JPATHT(PATH, TYPE, CODE)                 \
    if (json_match(parser, PATH, &i) == JSON_OK) \
    {                                            \
        SEEN(parser);                            \
        CHECK(TYPE);                             \
        CODE;                                    \
        return JSON_OK;                          \
    }

#define JSTRING(PATH, DEST)                       \
    if (json_match(parser, PATH, &i) == JSON_OK)  \
    {                                             \
        SEEN(parser);                             \
        CHECK2(JSON_TYPE_STRING, JSON_TYPE_NULL); \
        if (type == JSON_TYPE_NULL)               \
            DEST = NULL;                          \
        else                                      \
            strdupz(&(DEST), un->string);         \
        return JSON_OK;                           \
    }

static uint64_t hex2int(const char* digits, size_t num_digits)
{
    uint64_t r = 0;
    for (size_t i = 0; i < num_digits; i++)
    {
        char c = digits[i];
        r <<= 4;
        if (c >= '0' && c <= '9')
            r |= (c - '0') & 0xFF;
        else if (c >= 'a' && c <= 'f')
            r |= (0xA + (c - 'a')) & 0xFF;
        else if (c >= 'A' && c <= 'F')
            r |= (0xA + (c - 'A')) & 0xFF;
    }
    return r;
}

#define JINTDECLU(T, B)                                      \
    static json_result_t decode_##T(                         \
        json_parser_t* parser,                               \
        json_type_t type,                                    \
        const json_union_t* value,                           \
        char* path,                                          \
        size_t* index,                                       \
        T* to)                                               \
    {                                                        \
        if (!to)                                             \
            return JSON_BAD_PARAMETER;                       \
                                                             \
        if (json_match(parser, path, index) == JSON_OK)      \
        {                                                    \
            if (type != JSON_TYPE_STRING)                    \
                FAIL(                                        \
                    "invalid value type for '%s'\n",         \
                    parser->path[parser->depth - 1]);        \
            _Static_assert(                                  \
                sizeof(unsigned long) == 8,                  \
                "unexpected size of unsigned long");         \
            uint64_t tmp = strtoul(value->string, NULL, 10); \
            if (!(B))                                        \
                return JSON_UNKNOWN_VALUE;                   \
            else                                             \
            {                                                \
                *to = tmp;                                   \
                return JSON_OK;                              \
            }                                                \
        }                                                    \
        return JSON_NO_MATCH;                                \
    }

#define JINTDECLS(T, B)                                    \
    static json_result_t decode_##T(                       \
        json_parser_t* parser,                             \
        json_type_t type,                                  \
        const json_union_t* value,                         \
        char* path,                                        \
        size_t* index,                                     \
        T* to)                                             \
    {                                                      \
        if (!to)                                           \
            return JSON_BAD_PARAMETER;                     \
                                                           \
        if (json_match(parser, path, index) == JSON_OK)    \
        {                                                  \
            if (type != JSON_TYPE_STRING)                  \
                FAIL(                                      \
                    "invalid value type for '%s'\n",       \
                    parser->path[parser->depth - 1]);      \
            _Static_assert(                                \
                sizeof(unsigned long) == 8,                \
                "unexpected size of unsigned long");       \
            int64_t tmp = strtol(value->string, NULL, 10); \
            if (!(B))                                      \
                return JSON_UNKNOWN_VALUE;                 \
            else                                           \
            {                                              \
                *to = tmp;                                 \
                return JSON_OK;                            \
            }                                              \
        }                                                  \
        return JSON_NO_MATCH;                              \
    }

JINTDECLU(uint64_t, tmp <= UINT64_MAX);
JINTDECLS(int64_t, INT64_MIN <= tmp && tmp <= INT64_MAX);
JINTDECLU(uint32_t, tmp <= UINT32_MAX);
JINTDECLS(int32_t, INT32_MIN <= tmp && tmp <= INT32_MAX);
JINTDECLU(uint16_t, tmp <= UINT16_MAX);

#define JNULL(P)                                  \
    do                                            \
    {                                             \
        if (json_match(parser, P, &i) == JSON_OK) \
        {                                         \
            if (type == JSON_TYPE_NULL)           \
                return JSON_OK;                   \
        }                                         \
    } while (0);

#define JBOOL(P, D)                               \
    do                                            \
    {                                             \
        if (json_match(parser, P, &i) == JSON_OK) \
        {                                         \
            *(D) = un->boolean;                   \
            return JSON_OK;                       \
        }                                         \
    } while (0);

#define JU64(P, D)                                                          \
    if (decode_uint64_t(parser, JSON_TYPE_STRING, un, P, &i, D) == JSON_OK) \
        return JSON_OK;
#define JS64(P, D)                                                         \
    if (decode_int64_t(parser, JSON_TYPE_STRING, un, P, &i, D) == JSON_OK) \
        return JSON_OK;
#define JU32(P, D)                                                          \
    if (decode_uint32_t(parser, JSON_TYPE_STRING, un, P, &i, D) == JSON_OK) \
        return JSON_OK;
#define JS32(P, D)                                                         \
    if (decode_int32_t(parser, JSON_TYPE_STRING, un, P, &i, D) == JSON_OK) \
        return JSON_OK;
#define JU16(P, D)                                                          \
    if (decode_uint16_t(parser, JSON_TYPE_STRING, un, P, &i, D) == JSON_OK) \
        return JSON_OK;

static json_result_t json_read_app_config_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    json_result_t result = JSON_UNEXPECTED;
    json_callback_data_t* data = (json_callback_data_t*)callback_data;
    unsigned long i;

    switch (reason)
    {
        case JSON_REASON_NONE:
            FAIL("unreachable");
        case JSON_REASON_NAME:
            break;
        case JSON_REASON_BEGIN_OBJECT:
            if (json_match(parser, "app_config.disks", &i) == JSON_OK)
            {
                size_t new_count = data->array_count + 1;
                data->array = realloc(
                    data->array,
                    new_count * sizeof(sgxlkl_enclave_disk_config_t));
                if (!data->array)
                    FAIL("out of memory\n");
                sgxlkl_enclave_disk_config_t* disks =
                    (sgxlkl_enclave_disk_config_t*)data->array;
                for (size_t i = data->array_count; i < new_count; i++)
                    memset(&disks[i], 0, sizeof(sgxlkl_enclave_disk_config_t));
                data->array_count = new_count;
            }
            break;
        case JSON_REASON_END_OBJECT:
            break;
        case JSON_REASON_BEGIN_ARRAY:
            if (data->array || data->array_count != 0)
                FAIL("json: nested arrays not supported.");
            data->array = NULL;
            data->array_count = 0;
            break;
        case JSON_REASON_END_ARRAY:
            if (json_match(parser, "app_config.argv", &i) == JSON_OK)
            {
                data->app_config->argc = data->array_count;
                data->app_config->argv = (char**)data->array;
            }
            else if (json_match(parser, "app_config.envp", &i) == JSON_OK)
            {
                data->app_config->envc = data->array_count;
                data->app_config->envp = (char**)data->array;
            }
            else if (json_match(parser, "app_config.auxv", &i) == JSON_OK)
            {
                data->app_config->auxc = data->array_count;
                data->app_config->auxv = (Elf64_auxv_t**)data->array;
            }
            else if (json_match(parser, "app_config.disks", &i) == JSON_OK)
            {
                data->app_config->num_disks = data->array_count;
                data->app_config->disks =
                    (sgxlkl_enclave_disk_config_t*)data->array;
            }
            else if (json_match(parser, "app_config.peers", &i) == JSON_OK)
            {
                data->app_config->num_peers = data->array_count;
                data->app_config->peers =
                    (sgxlkl_enclave_wg_peer_config_t*)data->array;
            }
            else
                FAIL("unknown json array '%s'\n", make_path(parser));
            data->array = NULL;
            data->array_count = 0;
            break;
        case JSON_REASON_VALUE:
        {
            // show_path(parser);

            if (json_match(parser, "app_config", &i) == JSON_OK &&
                type == JSON_TYPE_NULL)
            {
                memset(data->app_config, 0, sizeof(sgxlkl_app_config_t));
                return JSON_OK;
            }
            JSTRING("app_config.run", data->app_config->run);
            JSTRING("app_config.cwd", data->app_config->cwd);
            JPATHT("app_config.argv", JSON_TYPE_STRING, {
                size_t new_count = data->array_count + 1;
                data->array = realloc(data->array, new_count * sizeof(char*));
                for (size_t i = data->array_count; i < new_count; i++)
                    ((char**)data->array)[i] = NULL;
                strdupz((char**)data->array + data->array_count, un->string);
                data->array_count = new_count;
            });
            JPATHT("app_config.envp", JSON_TYPE_STRING, {
                size_t new_count = data->array_count + 1;
                data->array = realloc(data->array, new_count * sizeof(char*));
                for (size_t i = data->array_count; i < new_count; i++)
                    ((char**)data->array)[i] = NULL;
                strdupz((char**)data->array + data->array_count, un->string);
                data->array_count = new_count;
            });

#define AUXV() (&((Elf64_auxv_t*)data->array)[data->array_count - 1])
            JNULL("app_config.auxv");
            JU64("app_config.auxv.a_type", &AUXV()->a_type);
            JU64("app_config.auxv.a_val", &AUXV()->a_un.a_val);

            JPATHT("app_config.exit_status", JSON_TYPE_STRING, {
                if (strcmp(un->string, "full"))
                    data->app_config->exit_status = EXIT_STATUS_FULL;
                else if (strcmp(un->string, "binary"))
                    data->app_config->exit_status = EXIT_STATUS_BINARY;
                else if (strcmp(un->string, "none"))
                    data->app_config->exit_status = EXIT_STATUS_NONE;
                else
                    FAIL("Invalid app_config.exit_status value.\n");
            });

#define APPDISK() \
    (&((sgxlkl_enclave_disk_config_t*)data->array)[data->array_count - 1])

            JBOOL("app_config.disks.create", &APPDISK()->create);
            JU64("app_config.disks.size", &APPDISK()->size);
            if (json_match(parser, "app_config.disks.mnt", &i) == JSON_OK)
            {
                SEEN(parser);
                size_t len = strlen(un->string);
                if (len > SGXLKL_DISK_MNT_MAX_PATH_LEN)
                    FAIL("invalid length of 'mnt' for disk %d\n", i);
                sgxlkl_enclave_disk_config_t* disk = APPDISK();
                memcpy(disk->mnt, un->string, len + 1);
                return JSON_OK;
            }
            JBOOL("app_config.disks.readonly", &APPDISK()->readonly);
            if (json_match(parser, "app_config.disks.key", &i) == JSON_OK)
            {
                SEEN(parser);
                CHECK2(JSON_TYPE_STRING, JSON_TYPE_NULL);
                sgxlkl_enclave_disk_config_t* disk = APPDISK();
                if (type == JSON_TYPE_NULL)
                    disk->key = NULL;
                else
                {
                    size_t l = strlen(un->string);
                    if (disk->key_len != 0 && disk->key_len != l / 2)
                        FAIL("contradictory key lengths for disk %d\n", i);
                    disk->key = calloc(1, l / 2);
                    if (!disk->key)
                        FAIL("out of memory\n");
                    for (size_t i = 0; i < l / 2; i++)
                        disk->key[i] = hex2int(un->string + 2 * i, 2);
                }
                return JSON_OK;
            }
            JSTRING("app_config.disks.key_id", APPDISK()->key_id);
            JU64("app_config.disks.key_len", &APPDISK()->key_len);
            JBOOL("app_config.disks.fresh_key", &APPDISK()->fresh_key);
            JSTRING("app_config.disks.roothash", APPDISK()->roothash);
            JU64(
                "app_config.disks.roothash_offset",
                &APPDISK()->roothash_offset);

            // else
            FAIL(
                "Unknown json element (or value for) '%s', refusing to run "
                "with this configuration.\n",
                make_path(parser));
        }
    }

    result = JSON_OK;

done:
    return result;
}

static json_result_t json_read_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    static char* last_path = NULL;
    json_result_t result = JSON_UNEXPECTED;
    json_callback_data_t* data = (json_callback_data_t*)callback_data;
    unsigned long i;

    switch (reason)
    {
        case JSON_REASON_NONE:
            FAIL("unreachable");
        case JSON_REASON_NAME:
            break;
        case JSON_REASON_BEGIN_OBJECT:
            if (json_match(parser, "disks", &i) == JSON_OK)
            {
                size_t new_count = data->array_count + 1;
                data->array = realloc(
                    data->array,
                    new_count * sizeof(sgxlkl_enclave_disk_config_t));
                if (!data->array)
                    FAIL("out of memory\n");
                sgxlkl_enclave_disk_config_t* disks =
                    (sgxlkl_enclave_disk_config_t*)data->array;
                for (size_t i = data->array_count; i < new_count; i++)
                    memset(&disks[i], 0, sizeof(sgxlkl_enclave_disk_config_t));
                data->array_count = new_count;
            }
            else
                result = json_read_app_config_callback(
                    parser, reason, type, un, data);
            break;
        case JSON_REASON_END_OBJECT:
            break;
        case JSON_REASON_BEGIN_ARRAY:
            if (data->array || data->array_count != 0)
                FAIL("json: nested arrays not supported.");
            data->array = NULL;
            data->array_count = 0;
            break;
        case JSON_REASON_END_ARRAY:
            if (json_match(parser, "wg.peers", &i) == JSON_OK)
            {
                data->config->wg.num_peers = data->array_count;
                data->config->wg.peers =
                    (sgxlkl_enclave_wg_peer_config_t*)data->array;
            }
            else if (json_match(parser, "clock_res", &i) == JSON_OK)
            {
                /* Nothing */
            }
            else if (
                json_read_app_config_callback(parser, reason, type, un, data) ==
                JSON_OK)
            {
                /* OK */
            }
            else
                FAIL("unknown json array '%s'\n", make_path(parser));
            data->array = NULL;
            data->array_count = 0;
            break;
        case JSON_REASON_VALUE:
        {
            // show_path(parser);

            char* cur_path = make_path(parser);
            if (last_path)
            {
                if (strcmp(last_path, cur_path) > 0)
                    FAIL("unsorted json: %s >= %s\n", last_path, cur_path);
                free(last_path);
            }
            last_path = cur_path;

            JU64("max_user_threads", &data->config->max_user_threads);
            JU64("stacksize", &data->config->stacksize);

#define HOSTDISK() \
    (&((sgxlkl_enclave_disk_config_t*)data->array)[data->array_count - 1])

            JBOOL("disks.create", &HOSTDISK()->create);
            JU64("disks.size", &HOSTDISK()->size);
            JPATHT("disks.mnt", JSON_TYPE_STRING, {
                size_t len = strlen(un->string);
                if (len > SGXLKL_DISK_MNT_MAX_PATH_LEN)
                    FAIL("invalid length of 'mnt' for disk %d\n", i);
                sgxlkl_enclave_disk_config_t* disk = HOSTDISK();
                memcpy(disk->mnt, un->string, len + 1);
            });

            JPATHT("mmap_files", JSON_TYPE_STRING, {
                if (strcmp(un->string, "shared") == 0)
                    data->config->mmap_files = ENCLAVE_MMAP_FILES_SHARED;
                else if (strcmp(un->string, "private") == 0)
                    data->config->mmap_files = ENCLAVE_MMAP_FILES_PRIVATE;
                else if (strcmp(un->string, "none") == 0)
                    data->config->mmap_files = ENCLAVE_MMAP_FILES_NONE;
                else
                    FAIL("invalid setting for mmap_files: %s\n", un->string);
            });
            JS32("net_fd", &data->config->net_fd);
            JU32("oe_heap_pagecount", &data->config->oe_heap_pagecount);
            JU32("net_ip4", &data->config->net_ip4);
            JU32("net_gw4", &data->config->net_gw4);
            JS32("net_mask4", &data->config->net_mask4);
            JPATHT("hostname", JSON_TYPE_STRING, {
                size_t len = strlen(un->string) + 1;
                if (len > sizeof(data->config->hostname))
                    FAIL("hostname too long");
                memcpy(data->config->hostname, un->string, len);
            });
            JS32("hostnet", &data->config->hostnet);
            JS32("tap_offload", &data->config->tap_offload);
            JS32("tap_mtu", &data->config->tap_mtu);

            JU32("wg.ip", &data->config->wg.ip);
            JU16("wg.listen_port", &data->config->wg.listen_port);
            JSTRING("wg.key", data->config->wg.key);

#define WGPEER() \
    (&((sgxlkl_enclave_wg_peer_config_t*)data->array)[data->array_count - 1])

            JSTRING("wg.peers.key", WGPEER()->key);
            JSTRING("wg.peers.allowed_ips", WGPEER()->allowed_ips);
            JSTRING("wg.peers.endpoint", WGPEER()->endpoint);

            JPATHT("argv", JSON_TYPE_STRING, {
                size_t new_count = data->array_count + 1;
                data->array = realloc(data->array, new_count * sizeof(char*));
                for (size_t i = data->array_count; i < new_count; i++)
                    ((char**)data->array)[i] = NULL;
                strdupz((char**)data->array + data->array_count, un->string);
                data->array_count = new_count;
            });
            JPATHT("envp", JSON_TYPE_STRING, {
                size_t new_count = data->array_count + 1;
                data->array = realloc(data->array, new_count * sizeof(char*));
                for (size_t i = data->array_count; i < new_count; i++)
                    ((char**)data->array)[i] = NULL;
                strdupz((char**)data->array + data->array_count, un->string);
                data->array_count = new_count;
            });

            JU64("espins", &data->config->espins);
            JU64("esleep", &data->config->esleep);
            JS64("sysconf_nproc_conf", &data->config->sysconf_nproc_conf);
            JS64("sysconf_nproc_onln", &data->config->sysconf_nproc_onln);

            JPATHT("clock_res", JSON_TYPE_STRING, {
                size_t len = strlen(un->string);
                if (len != 16)
                    FAIL("invalid length of value for clock_res");
                long tv_sec = hex2int(un->string, 8);
                long tv_nsec = hex2int(un->string + 8, 8);
                data->config->clock_res[i].tv_sec = tv_sec;
                data->config->clock_res[i].tv_nsec = tv_nsec;
                data->array_count++;
            });

            JS32("mode", &data->config->mode);
            JBOOL("fsgsbase", &data->config->fsgsbase);
            JBOOL("verbose", &data->config->verbose);
            JBOOL("kernel_verbose", &data->config->kernel_verbose);
            JSTRING("kernel_cmd", data->config->kernel_cmd);
            JSTRING("sysctl", data->config->sysctl);
            JBOOL("swiotlb", &data->config->swiotlb);

            if (json_read_app_config_callback(parser, reason, type, un, data) ==
                JSON_OK)
                return JSON_OK;

            // else
            FAIL(
                "Unknown json element '%s', refusing to run with this "
                "configuration.\n",
                make_path(parser));
        }
    }

    result = JSON_OK;

done:
    return result;
}

static void flatten_stack_strings(
    const json_callback_data_t* callback_data,
    sgxlkl_app_config_t* app_cfg)
{
    int have_run = app_cfg->run != NULL;
    size_t total_size = 0;
    size_t total_count = 1;
    if (have_run)
    {
        total_size += strlen(app_cfg->run) + 1;
        total_count++;
    }
    for (size_t i = 0; i < app_cfg->argc; i++)
        total_size += strlen(app_cfg->argv[i]) + 1;
    total_count += app_cfg->argc + 1;
    for (size_t i = 0; i < app_cfg->envc; i++)
    {
        total_size += strlen(app_cfg->envp[i]) + 1;
        total_count += app_cfg->envc + 1;
    }
    total_count += 1; // auxv terminator
    total_count += 1; // platform-tdependent stuff terminator

    char* buf = calloc(total_size, sizeof(char));
    char** out = calloc(total_count, sizeof(char*));

    size_t j = 0;
    char* buf_ptr = buf;

#define ADD_STRING(S)               \
    {                               \
        size_t len = strlen(S) + 1; \
        memcpy(buf_ptr, (S), len);  \
        out[j++] = buf_ptr;         \
        buf_ptr += len;             \
        free((void*)S);             \
        S = NULL;                   \
    }

    // argv
    if (have_run)
    {
        ADD_STRING(app_cfg->run);
    }
    for (size_t i = 0; i < app_cfg->argc; i++)
        ADD_STRING(app_cfg->argv[i]);
    app_cfg->argc = j;
    out[j++] = NULL;
    // envp
    for (size_t i = 0; i < app_cfg->envc; i++)
        ADD_STRING(app_cfg->envp[i]);
    out[j++] = NULL;
    for (size_t i = 0; i < app_cfg->auxc; i++)
    {
        out[j++] = (char*)app_cfg->auxv[i]->a_type;
        out[j++] = (char*)app_cfg->auxv[i]->a_un.a_val;
    }
    out[j++] = NULL;
    // TODO: platform independent things?
    out[j++] = NULL;

    app_cfg->argv = out;
    app_cfg->envp = out + app_cfg->argc + 1;
}

void check_config(const sgxlkl_enclave_config_t* cfg)
{
#define CONFCHECK(C, M) \
    if (C)              \
        FAIL("rejecting enclave configuration: " M "\n");

    const sgxlkl_app_config_t* app_cfg = &cfg->app_config;
    CONFCHECK(app_cfg->argv == NULL, "missing argv");
    CONFCHECK(app_cfg->argc < 0, "invalid argc");
    CONFCHECK(app_cfg->argc == 0, "argc == 0");
    CONFCHECK(app_cfg->envc < 0, "invalid envc");
}

int sgxlkl_read_enclave_config(const char* from, sgxlkl_enclave_config_t** to)
{
    if (!from || !to)
        return 1;

    *to = calloc(1, sizeof(sgxlkl_enclave_config_t));

    if (!*to)
        FAIL("out of memory\n");

    sgxlkl_app_config_t* app_config = &(*to)->app_config;
    json_parser_t parser;
    json_result_t r = JSON_UNEXPECTED;
    json_callback_data_t callback_data = {.config = *to,
                                          .app_config = app_config,
                                          .buffer_sz = 0,
                                          .index = 0,
                                          .seen = NULL,
                                          .array = NULL,
                                          .array_count = 0,
                                          .auxc = 0};

    // parser destroys `from`, so we copy it first.
    size_t json_len = strlen(from);
    char* json_copy = malloc(sizeof(char) * (json_len + 1));
    memcpy(json_copy, from, json_len);

    if ((r = json_parser_init(
             &parser,
             json_copy,
             strlen(from),
             json_read_callback,
             &callback_data)) != JSON_OK)
    {
        FAIL("json_parser_init() failed: %d\n", r);
    }

    if ((r = json_parser_parse(&parser)) != JSON_OK)
    {
        FAIL("json_parser_parse() failed: %d\n", r);
    }

    if (parser.depth != 0)
    {
        FAIL("unterminated json objects\n");
    }

    string_list_free(callback_data.seen);
    free(json_copy);

    flatten_stack_strings(&callback_data, app_config);
    check_config(*to);

    return 0;
}

void sgxlkl_default_enclave_config(sgxlkl_enclave_config_t* enclave_config)
{
    _Static_assert(
        sizeof(sgxlkl_enclave_config_t) == 416,
        "unexpected size of sgxlkl_enclave_config_t");

    // TODO
}

void sgxlkl_free_enclave_config(sgxlkl_enclave_config_t* enclave_config)
{
    // TODO: free more

    for (size_t i = 0; i < enclave_config->app_config.num_disks; i++)
    {
        free(enclave_config->app_config.disks[i].key);
        free(enclave_config->app_config.disks[i].key_id);
        free(enclave_config->app_config.disks[i].roothash);
    }
    free(enclave_config->app_config.disks);
    free(enclave_config);
}