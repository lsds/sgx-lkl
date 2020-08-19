#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>
#include "enclave/wireguard.h"
#include "host/env.h"
#include "host/sgxlkl_util.h"
#include "shared/sgxlkl_enclave_config.h"
#include "shared/util.h"

#include "host/serialize_enclave_config.h"

#define FAIL sgxlkl_host_fail
#define VERB sgxlkl_host_verbose

typedef struct json_obj
{
    char* key;
    json_type_t type;
    union {
        char* string;
        bool boolean;
    } value;
    struct json_obj** array;
    struct json_obj** objects;
    size_t size;
} json_obj_t;

static json_obj_t* create_json_obj(
    const char* key,
    json_type_t type,
    json_obj_t** array,
    json_obj_t** objects,
    size_t size)
{
    json_obj_t* r = calloc(1, sizeof(json_obj_t));
    if (!r)
        FAIL("out of memory\n");
    if (key)
        r->key = strdup(key);
    r->type = type;
    r->value.string = NULL;
    r->array = array;
    r->objects = objects;
    r->size = size;
    return r;
}

static json_obj_t* create_json_string(const char* key, const char* value)
{
    json_obj_t* obj = create_json_obj(key, JSON_TYPE_STRING, NULL, NULL, 0);
    if (value)
    {
        obj->value.string = strdup(value);
        if (!obj->value.string)
            FAIL("out of memory\n");
    }
    return obj;
}

static json_obj_t* create_json_objects(const char* key, size_t len)
{
    json_obj_t* r = create_json_obj(key, JSON_TYPE_NULL, NULL, NULL, len);
    r->objects = calloc(len, sizeof(json_obj_t*));
    if (!r->objects)
        FAIL("out of memory\n");
    return r;
}

static json_obj_t* create_json_array(const char* key, size_t len)
{
    json_obj_t* r = create_json_obj(key, JSON_TYPE_NULL, NULL, NULL, len);
    r->array = calloc(len, sizeof(char*));
    if (!r->array)
        FAIL("out of memory\n");
    return r;
}

static json_obj_t* encode_hex_string(
    const char* key,
    const uint8_t* buf,
    size_t buf_sz)
{
    json_obj_t* obj = create_json_obj(key, JSON_TYPE_STRING, NULL, NULL, 0);
    if (buf && buf_sz > 0)
    {
        size_t len = 2 * buf_sz + 1;
        obj->value.string = malloc(len);
        if (!obj->value.string)
            FAIL("out of memory\n");
        bytes_to_hex(obj->value.string, len, buf, buf_sz);
    }
    else
        obj->value.string = strdup("");
    return obj;
}

static json_obj_t* encode_boolean(const char* key, const bool value)
{
    json_obj_t* obj = create_json_obj(key, JSON_TYPE_BOOLEAN, NULL, NULL, 0);
    obj->value.boolean = value;
    return obj;
}

static json_obj_t* encode_int(const char* key, uint64_t value, const char* fmt)
{
    size_t len = 8 * 2 + 1;
    char* tmp = calloc(1, len);
    if (!tmp)
        FAIL("out of memory\n");
    snprintf(tmp, len, fmt, value);
    return create_json_string(key, tmp);
}

static json_obj_t* encode_uint32(const char* key, uint32_t value)
{
    return encode_int(key, value, "%" PRIu32);
}

static json_obj_t* encode_uint64(const char* key, uint64_t value)
{
    return encode_int(key, value, "%" PRIu64);
}

static json_obj_t* encode_string_array(
    const char* key,
    char* const* strings,
    size_t num_strings)
{
    json_obj_t* res = create_json_array(key, num_strings);
    if (num_strings == 0)
        res->array = malloc(1);
    for (size_t i = 0; i < num_strings; i++)
        res->array[i] = create_json_string(NULL, strings[i]);
    return res;
}

static json_obj_t* encode_clock_res(
    const char* key,
    const sgxlkl_clock_res_config_t* clock_res)
{
    json_obj_t* res = create_json_array(key, 8);
    for (size_t i = 0; i < 8; i++)
    {
        res->array[i] = create_json_objects(NULL, 1);
        res->array[i]->objects[0] =
            create_json_string("resolution", clock_res[i].resolution);
    }
    return res;
}

static json_obj_t* encode_root(
    const char* key,
    const sgxlkl_enclave_root_config_t* root)
{
    _Static_assert(
        sizeof(sgxlkl_enclave_root_config_t) == 48,
        "sgxlkl_enclave_root_config_t size has changed");

    json_obj_t* r = create_json_objects(key, 6);
    r->objects[0] = encode_hex_string("key", root->key, root->key_len);
    r->objects[1] = create_json_string("key_id", root->key_id);
    r->objects[2] = create_json_string("roothash", root->roothash);
    r->objects[3] = encode_uint64("roothash_offset", root->roothash_offset);
    r->objects[4] = encode_boolean("readonly", root->readonly);
    r->objects[5] = encode_boolean("overlay", root->overlay);
    return r;
}

static json_obj_t* encode_mounts(
    const char* key,
    const sgxlkl_enclave_mount_config_t* mounts,
    size_t num_mounts)
{
    json_obj_t* r = create_json_array(key, num_mounts);
    for (size_t i = 0; i < num_mounts; i++)
    {
        _Static_assert(
            sizeof(sgxlkl_enclave_mount_config_t) == 320,
            "sgxlkl_enclave_disk_config_t size has changed");

        r->array[i] = create_json_objects(NULL, 9);
        r->array[i]->objects[0] =
            create_json_string("destination", mounts[i].destination);
        r->array[i]->objects[1] =
            encode_hex_string("key", mounts[i].key, mounts[i].key_len);
        r->array[i]->objects[2] =
            create_json_string("key_id", mounts[i].key_id);
        r->array[i]->objects[3] =
            encode_boolean("fresh_key", mounts[i].fresh_key);
        r->array[i]->objects[4] =
            create_json_string("roothash", mounts[i].roothash);
        r->array[i]->objects[5] =
            encode_uint64("roothash_offset", mounts[i].roothash_offset);
        r->array[i]->objects[6] =
            encode_boolean("readonly", mounts[i].readonly);
        r->array[i]->objects[7] = encode_boolean("create", mounts[i].create);
        r->array[i]->objects[8] = encode_uint64("size", mounts[i].size);
    }
    return r;
}

static json_obj_t* encode_wg_peers(
    const char* key,
    const sgxlkl_enclave_wg_peer_config_t* peers,
    size_t num_peers)
{
    _Static_assert(
        sizeof(sgxlkl_enclave_wg_peer_config_t) == 24,
        "sgxlkl_enclave_wg_peer_config_t size has changed");

    json_obj_t* r = create_json_array(key, num_peers);
    for (size_t i = 0; i < num_peers; i++)
    {
        create_json_objects(key, 4);
        r->objects[i] = create_json_objects(NULL, 3);
        r->objects[i]->objects[0] = create_json_string("key", peers[i].key);
        r->objects[i]->objects[1] =
            create_json_string("allowed_ips", peers[i].allowed_ips);
        r->objects[i]->objects[2] =
            create_json_string("endpoint", peers[i].endpoint);
    }
    return r;
}

static json_obj_t* encode_wg(
    const char* key,
    const sgxlkl_enclave_wg_config_t* wg)
{
    _Static_assert(
        sizeof(sgxlkl_enclave_wg_config_t) == 40,
        "sgxlkl_enclave_wg_config_t size has changed");

    json_obj_t* r = create_json_objects(key, 4);
    r->objects[0] = create_json_string("ip", wg->ip);
    r->objects[1] = encode_uint32("listen_port", wg->listen_port);
    r->objects[2] = create_json_string("key", wg->key);
    r->objects[3] = encode_wg_peers("peers", wg->peers, wg->num_peers);

    return r;
}

static json_obj_t* encode_image_sizes(
    char* key,
    const sgxlkl_image_sizes_config_t* sizes)
{
    _Static_assert(
        sizeof(sgxlkl_image_sizes_config_t) == 16,
        "sgxlkl_image_sizes_config_t size has changed");

    json_obj_t* r = create_json_objects(key, 2);
    r->objects[0] = encode_uint64("num_heap_pages", sizes->num_heap_pages);
    r->objects[1] = encode_uint64("num_stack_pages", sizes->num_stack_pages);
    return r;
}

static json_obj_t* encode_io(char* key, const sgxlkl_io_config_t* io)
{
    _Static_assert(
        sizeof(sgxlkl_io_config_t) == 3,
        "sgxlkl_image_sizes_config_t size has changed");

    json_obj_t* r = create_json_objects(key, 3);
    r->objects[0] = encode_boolean("console", io->console);
    r->objects[1] = encode_boolean("block", io->block);
    r->objects[2] = encode_boolean("network", io->network);
    return r;
}

#ifndef SGXLKL_RELEASE
static bool get_config_env(
    const char* name,
    const sgxlkl_enclave_config_t* config)
{
    size_t name_len = strlen(name);
    for (size_t i = 0; i < config->num_env; i++)
    {
        const char* setting = config->env[i];
        if (strncmp(name, setting, name_len) == 0 && setting[name_len] == '=')
            return strcmp(setting + name_len, "1") == 0;
    }
    for (size_t i = 0; i < config->num_host_import_env; i++)
    {
        const char* import_name = config->host_import_env[i];
        if (strncmp(name, import_name, name_len) == 0)
            return getenv_bool(name, 0);
    }
    return false;
}

static json_obj_t* encode_tracing_options(
    char* key,
    const sgxlkl_enclave_config_t* config)
{
    _Static_assert(
        sizeof(sgxlkl_trace_config_t) == 11,
        "sgxlkl_trace_config_t size has changed");

    json_obj_t* r = create_json_objects(key, 10);
    r->objects[0] = encode_boolean(
        "print_app_runtime",
        get_config_env("SGXLKL_PRINT_APP_RUNTIME", config));
    r->objects[1] = encode_boolean(
        "syscall",
        ((get_config_env("SGXLKL_TRACE_SYSCALL", config) ||
          get_config_env("SGXLKL_TRACE_LKL_SYSCALL", config))));
    r->objects[2] = encode_boolean(
        "internal_syscall",
        ((get_config_env("SGXLKL_TRACE_SYSCALL", config) ||
          get_config_env("SGXLKL_TRACE_INTERNAL_SYSCALL", config))));
    r->objects[3] = encode_boolean(
        "ignored_syscall",
        ((get_config_env("SGXLKL_TRACE_SYSCALL", config) ||
          get_config_env("SGXLKL_TRACE_IGNORED_SYSCALL", config))));
    r->objects[4] = encode_boolean(
        "unsupported_syscall",
        ((get_config_env("SGXLKL_TRACE_SYSCALL", config) ||
          get_config_env("SGXLKL_TRACE_UNSUPPORTED_SYSCALL", config))));
    r->objects[5] = encode_boolean(
        "redirect_syscall",
        get_config_env("SGXLKL_TRACE_REDIRECT_SYSCALL", config));
    r->objects[6] =
        encode_boolean("mmap", get_config_env("SGXLKL_TRACE_MMAP", config));
    r->objects[7] =
        encode_boolean("signal", get_config_env("SGXLKL_TRACE_SIGNAL", config));
    r->objects[8] =
        encode_boolean("thread", get_config_env("SGXLKL_TRACE_THREAD", config));
    r->objects[9] =
        encode_boolean("disk", get_config_env("SGXLKL_TRACE_DISK", config));
    return r;
}
#endif

static void print_to_buffer(
    char** buffer,
    size_t* buffer_size,
    char** position,
    char* string)
{
    size_t len = strlen(string) + 1;
    size_t remaining = *buffer_size - (*position - *buffer);
    if (len >= remaining)
    {
        size_t pos_offset = *position - *buffer;
        size_t min = *buffer_size + len - remaining;
        *buffer_size = *buffer_size * 2 < min ? min : *buffer_size * 2;
        *buffer = realloc(*buffer, *buffer_size);
        if (!*buffer)
            FAIL("out of memory");
        *position = *buffer + pos_offset;
    }
    memcpy(*position, string, len);
    *position += len - 1;
}

static void print_json(
    char** buffer,
    size_t* buffer_size,
    char** position,
    json_obj_t* obj)
{
    if (obj->key)
    {
        print_to_buffer(buffer, buffer_size, position, "\"");
        print_to_buffer(buffer, buffer_size, position, obj->key);
        print_to_buffer(buffer, buffer_size, position, "\":");
    }

    if (obj->type == JSON_TYPE_BOOLEAN)
    {
        print_to_buffer(
            buffer,
            buffer_size,
            position,
            obj->value.boolean ? "true" : "false");
    }
    else if (obj->type == JSON_TYPE_STRING)
    {
        if (obj->value.string == NULL)
        {
            print_to_buffer(buffer, buffer_size, position, "null");
        }
        else
        {
            print_to_buffer(buffer, buffer_size, position, "\"");

            char* val_copy = strdup(obj->value.string);
            char* remaining = val_copy;
            while (remaining)
            {
                char* quotes = strchr(remaining, '\"');
                if (!quotes)
                {
                    print_to_buffer(buffer, buffer_size, position, remaining);
                    remaining = NULL;
                }
                else
                {
                    *quotes = 0;
                    print_to_buffer(buffer, buffer_size, position, remaining);
                    print_to_buffer(buffer, buffer_size, position, "\\\"");
                    remaining = quotes + 1;
                }
            }
            free(val_copy);
            print_to_buffer(buffer, buffer_size, position, "\"");
        }
    }
    else if (obj->array)
    {
        print_to_buffer(buffer, buffer_size, position, "[");
        for (size_t i = 0; i < obj->size; i++)
        {
            if (i != 0)
                print_to_buffer(buffer, buffer_size, position, ",");
            print_json(buffer, buffer_size, position, obj->array[i]);
        }
        print_to_buffer(buffer, buffer_size, position, "]");
    }
    else if (obj->objects)
    {
        print_to_buffer(buffer, buffer_size, position, "{");
        for (size_t i = 0; i < obj->size; i++)
        {
            if (i != 0)
                print_to_buffer(buffer, buffer_size, position, ",");
            print_json(buffer, buffer_size, position, obj->objects[i]);
        }
        print_to_buffer(buffer, buffer_size, position, "}");
    }
    else if (obj->key != NULL && obj->type == JSON_TYPE_NULL)
    {
        print_to_buffer(buffer, buffer_size, position, "null");
    }
    else
        FAIL("Unidentified json object\n");
}

static void free_json(json_obj_t* obj)
{
    if (obj)
    {
        free(obj->key);
        if (obj->type == JSON_TYPE_STRING)
            free(obj->value.string);
        if (obj->array)
            for (size_t i = 0; i < obj->size; i++)
                free_json(obj->array[i]);
        free(obj->array);
        if (obj->objects)
            for (size_t i = 0; i < obj->size; i++)
                free_json(obj->objects[i]);
        free(obj->objects);
    }
}

static bool is_json_object(const json_obj_t* obj)
{
    return obj->type == JSON_TYPE_NULL && !obj->array && obj->objects;
}

static bool is_json_array(const json_obj_t* obj)
{
    return obj->type == JSON_TYPE_NULL && obj->array && !obj->objects;
}

static void sort_json(json_obj_t* obj)
{
    if (is_json_object(obj) && obj->size > 0)
    {
        for (size_t i = 0; i < obj->size; i++)
            sort_json(obj->objects[i]);

        for (size_t i = 0; i < obj->size; i++)
        {
            if (i == 0)
                continue;

            const char* last = obj->objects[i - 1]->key;
            const char* cur = obj->objects[i]->key;
            if (last == NULL || cur == NULL)
                FAIL("invalid json object entries without keys\n");
            int cmp = strcmp(last, cur);
            if (cmp < 0) /* OK */
                ;
            else if (cmp == 0)
                FAIL("duplicate keys in json object");
            else if (cmp > 0)
            {
                json_obj_t* t = obj->objects[i - 1];
                obj->objects[i - 1] = obj->objects[i];
                obj->objects[i] = t;
                i -= 2;
            }
        }
    }
    else if (is_json_array(obj))
    {
        for (size_t i = 0; i < obj->size; i++)
            sort_json(obj->array[i]);
    }
}

void serialize_enclave_config(
    const sgxlkl_enclave_config_t* config,
    char** buffer,
    size_t* buffer_size)
{
    if (!buffer || !buffer_size)
        FAIL("no buffer for config");

    // Catch modifications to sgxlkl_enclave_config_t early. If this fails,
    // the code above/below needs adjusting for the added/removed settings.
    _Static_assert(
        sizeof(sgxlkl_enclave_config_t) == 472,
        "sgxlkl_enclave_config_t size has changed");

#define FPFBOOL(N) root->objects[cnt++] = encode_boolean(#N, config->N)
#define FPFS32(N) root->objects[cnt++] = mk_json_s32(#N, config->N)
#define FPFU32(N) root->objects[cnt++] = encode_uint32(#N, config->N)
#define FPFU64(N) root->objects[cnt++] = encode_uint64(#N, config->N)
#define FPFS(N) root->objects[cnt++] = create_json_string(#N, config->N)
#define FPFSS(N, S) root->objects[cnt++] = create_json_string(#N, S)

    size_t root_size =
        sizeof(sgxlkl_enclave_config_t); // way more than necessary
    json_obj_t* root = create_json_objects(NULL, root_size);

    size_t cnt = 0;
    root->objects[cnt++] =
        encode_uint64("format_version", SGXLKL_ENCLAVE_CONFIG_T_VERSION);
    FPFSS(mode, sgxlkl_enclave_mode_t_to_string(config->mode));
    FPFU64(stacksize);
    FPFSS(
        mmap_files, sgxlkl_enclave_mmap_files_t_to_string(config->mmap_files));
    FPFU64(oe_heap_pagecount);

    FPFS(net_ip4);
    FPFS(net_gw4);
    FPFS(net_mask4);
    FPFS(hostname);
    FPFU32(tap_mtu);
    FPFBOOL(hostnet);
    root->objects[cnt++] = encode_wg("wg", &config->wg);

    FPFU64(max_user_threads);
    FPFU64(espins);
    FPFU64(esleep);
    FPFU64(ethreads);
    root->objects[cnt++] = encode_clock_res("clock_res", config->clock_res);

    FPFBOOL(fsgsbase);
    FPFBOOL(verbose);
    FPFBOOL(kernel_verbose);
    FPFS(kernel_cmd);
    FPFS(sysctl);
    FPFBOOL(swiotlb);

    FPFS(cwd);
    root->objects[cnt++] =
        encode_string_array("args", config->args, config->num_args);
    root->objects[cnt++] =
        encode_string_array("env", config->env, config->num_env);
    root->objects[cnt++] = encode_string_array(
        "host_import_env",
        config->host_import_env,
        config->num_host_import_env);
    root->objects[cnt++] = encode_root("root", &config->root);
    root->objects[cnt++] =
        encode_mounts("mounts", config->mounts, config->num_mounts);

    FPFSS(
        exit_status, sgxlkl_exit_status_mode_t_to_string(config->exit_status));

    root->objects[cnt++] =
        encode_image_sizes("image_sizes", &config->image_sizes);

    root->objects[cnt++] = encode_io("io", &config->io);

#ifndef SGXLKL_RELEASE
    root->objects[cnt++] = encode_tracing_options("trace", config);
#endif

    root->size = cnt;

    sort_json(root);

    char* position = *buffer;
    print_json(buffer, buffer_size, &position, root);

    VERB("Enclave config: %s\n", *buffer);

    free_json(root);
}
