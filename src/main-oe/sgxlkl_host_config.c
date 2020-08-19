#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include "host/env.h"
#include "host/sgxlkl_host_config.h"
#include "host/sgxlkl_params.h"
#include "host/sgxlkl_util.h"

#define FAIL sgxlkl_host_fail

#define CHECKMEM(C) \
    if (!C)         \
        FAIL("out of memory\n");

typedef struct json_callback_data
{
    sgxlkl_host_config_t* config;
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

    return strdup(tmp);
}

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
        CODE;             \
        return JSON_OK;   \
    }

#define JPATHT(PATH, TYPE, CODE) \
    if (MATCH(PATH))             \
    {                            \
        CHECK(TYPE);             \
        CODE;                    \
        return JSON_OK;          \
    }

#define JPATH2T(PATH, TYPE1, TYPE2, CODE) \
    if (MATCH(PATH))                      \
    {                                     \
        CHECK2(TYPE1, TYPE2);             \
        CODE;                             \
        return JSON_OK;                   \
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

#define JSTRING(PATH, DEST)                           \
    JPATH2T(PATH, JSON_TYPE_STRING, JSON_TYPE_NULL, { \
        if (!un || un->string == NULL)                \
            DEST = NULL;                              \
        else                                          \
        {                                             \
            errno = 0;                                \
            DEST = strdup(un->string);                \
            if (errno != 0)                           \
                return JSON_FAILED;                   \
        }                                             \
        return JSON_OK;                               \
    });

#define JBOOL(PATH, DEST) \
    JPATHT(PATH, JSON_TYPE_BOOLEAN, (DEST) = un->boolean;);

#define ALLOC_ARRAY(N, A, T)                              \
    do                                                    \
    {                                                     \
        data->config->N = un->integer;                    \
        data->config->A = calloc(un->integer, sizeof(T)); \
        CHECKMEM(data->config->A);                        \
    } while (0)

static sgxlkl_host_mount_config_t* _mount(
    sgxlkl_host_config_t* cfg,
    json_parser_t* parser)
{
    size_t i = json_get_array_index(parser);
    if (i == -1)
        FAIL("invalid array index\n");
    return &cfg->mounts[i];
}

static json_result_t parse_host_config_entry(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callbackdata)
{
    json_callback_data_t* data = (json_callback_data_t*)callbackdata;
    sgxlkl_host_config_t* cfg = data->config;

    switch (reason)
    {
        case JSON_REASON_NONE:
            assert("unreachable");
        case JSON_REASON_NAME:
            break;
        case JSON_REASON_BEGIN_OBJECT:
            break;
        case JSON_REASON_END_OBJECT:
            break;
        case JSON_REASON_BEGIN_ARRAY:
            if (MATCH("mounts"))
                ALLOC_ARRAY(num_mounts, mounts, sgxlkl_host_mount_config_t);
            break;
        case JSON_REASON_END_ARRAY:
            break;
        case JSON_REASON_VALUE:
        {
            JSTRING("root.image_path", cfg->root.image_path);
            JSTRING("root.key", cfg->root.key);
            JBOOL("root.overlay", cfg->root.overlay);
            JBOOL("root.readonly", cfg->root.readonly);
            JSTRING("root.verity", cfg->root.verity);
            JSTRING("root.verity_offset", cfg->root.verity_offset);

#define MOUNT() _mount(data->config, parser)
            JSTRING("mounts.image_path", MOUNT()->image_path);
            JSTRING("mounts.destination", MOUNT()->destination);
            JBOOL("mounts.readonly", MOUNT()->readonly);

            JBOOL("verbose", cfg->verbose);
            JSTRING("ethreads_affinity", cfg->ethreads_affinity);
            JSTRING("tap_device", cfg->tap_device);
            JBOOL("tap_offload", cfg->tap_offload);

            sgxlkl_host_warn("Unknown json path: %s.\n", make_path(parser));
            break;
        }
        default:
            sgxlkl_host_warn("Unknown json reason %d.\n", reason);
            break;
    }

    return JSON_OK;
}

int sgxlkl_read_host_config(
    char* from,
    sgxlkl_host_config_t* config,
    char** err)
{
    static char tmp[1024];
    json_parser_t parser;
    json_parser_options_t options;
    options.allow_whitespace = true;
    json_result_t r = JSON_UNEXPECTED;
    json_callback_data_t callback_data = {.config = config};

    // parser destroys `from`, so we copy it first.
    size_t json_len = strlen(from);
    char* json_copy = malloc(sizeof(char) * (json_len + 1));
    memcpy(json_copy, from, json_len);

    json_allocator_t allocator = {.ja_malloc = malloc, .ja_free = free};

    if ((r = json_parser_init(
             &parser,
             json_copy,
             strlen(from),
             parse_host_config_entry,
             &callback_data,
             &allocator,
             &options)) != JSON_OK)
    {
        snprintf(tmp, sizeof(tmp), "json_parser_init() failed: %d", r);
        *err = strdup(tmp);
        return -1;
    }

    if ((r = json_parser_parse(&parser)) != JSON_OK)
    {
        snprintf(tmp, sizeof(tmp), "json_parser_parse() failed: %d", r);
        *err = strdup(tmp);
        return -1;
    }

    if (parser.depth != 0)
    {
        snprintf(tmp, sizeof(tmp), "unterminated json objects");
        *err = strdup(tmp);
        return -1;
    }

    free(json_copy);

    return 0;
}

int sgxlkl_read_host_config_from_file(
    const char* path,
    sgxlkl_host_config_t* config,
    char** err)
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

    int res = sgxlkl_read_host_config(buf, config, err);
    free(buf);
    return res;
}

int sgxlkl_config_bool(const char* key)
{
    return getenv_bool(key, false);
}

uint64_t sgxlkl_config_uint64(const char* key)
{
    return getenv_uint64(key, 0, UINT64_MAX);
}

char* sgxlkl_config_str(const char* key)
{
    return getenv_str(key, NULL);
}

bool sgxlkl_config_overridden(const char* key)
{
    return getenv(key) != NULL;
}