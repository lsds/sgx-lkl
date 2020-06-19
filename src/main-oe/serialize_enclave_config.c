#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>
#include "enclave/enclave_mem.h"
#include "enclave/wireguard.h"
#include "host/sgxlkl_util.h"
#include "shared/env.h"
#include "shared/host_state.h"
#include "shared/sgxlkl_enclave_config.h"

#include "host/serialize_enclave_config.h"

#define FAIL sgxlkl_host_fail
#define INFO sgxlkl_host_info

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

static json_obj_t* mk_json_obj(
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

static json_obj_t* mk_json_string(const char* key, const char* value)
{
    json_obj_t* obj = mk_json_obj(key, JSON_TYPE_STRING, NULL, NULL, 0);
    if (value)
    {
        obj->value.string = strdup(value);
        if (!obj->value.string)
            FAIL("out of memory\n");
    }
    return obj;
}

static json_obj_t* mk_json_hex_string(
    const char* key,
    const uint8_t* buf,
    size_t buf_sz)
{
    json_obj_t* obj = mk_json_obj(key, JSON_TYPE_STRING, NULL, NULL, 0);
    if (buf && buf_sz > 0)
    {
        size_t len = 2 * buf_sz + 1;
        obj->value.string = malloc(len);
        if (!obj->value.string)
            FAIL("out of memory\n");
        bytes_to_hex(obj->value.string, len, buf, buf_sz);
    }
    return obj;
}

static json_obj_t* mk_json_boolean(const char* key, const bool value)
{
    json_obj_t* obj = mk_json_obj(key, JSON_TYPE_BOOLEAN, NULL, NULL, 0);
    obj->value.boolean = value;
    return obj;
}

static json_obj_t* mk_json_array(const char* key, size_t len)
{
    json_obj_t* r = mk_json_obj(key, JSON_TYPE_NULL, NULL, NULL, len);
    r->array = calloc(len, sizeof(char*));
    if (!r->array)
        FAIL("out of memory\n");
    return r;
}

static json_obj_t* mk_json_objects(const char* key, size_t len)
{
    json_obj_t* r = mk_json_obj(key, JSON_TYPE_NULL, NULL, NULL, len);
    r->objects = calloc(len, sizeof(json_obj_t*));
    if (!r->objects)
        FAIL("out of memory\n");
    return r;
}

static json_obj_t* mk_json_int(const char* key, uint64_t value, const char* fmt)
{
    size_t len = 8 * 2 + 1;
    char* tmp = calloc(1, len);
    if (!tmp)
        FAIL("out of memory\n");
    snprintf(tmp, len, fmt, value);
    return mk_json_string(key, tmp);
}

static json_obj_t* mk_json_u32(const char* key, uint32_t value)
{
    return mk_json_int(key, value, "%" PRIu32);
}

static json_obj_t* mk_json_u64(const char* key, uint64_t value)
{
    return mk_json_int(key, value, "%" PRIu64);
}

static json_obj_t* mk_json_string_array(
    const char* key,
    char* const* strings,
    size_t num_strings)
{
    json_obj_t* res = mk_json_array(key, num_strings);
    if (num_strings == 0)
        res->array = malloc(1);
    for (size_t i = 0; i < num_strings; i++)
        res->array[i] = mk_json_string(NULL, strings[i]);
    return res;
}

static json_obj_t* mk_json_string_clock_res(
    const char* key,
    const sgxlkl_clock_res_config_t* clock_res)
{
    json_obj_t* res = mk_json_array(key, 8);
    for (size_t i = 0; i < 8; i++)
    {
        res->array[i] = mk_json_string(NULL, clock_res[i].resolution);
    }
    return res;
}

static json_obj_t* mk_json_disks(
    const char* key,
    sgxlkl_enclave_disk_config_t* disks,
    size_t num_disks)
{
    json_obj_t* r = mk_json_array(key, num_disks);
    for (size_t i = 0; i < num_disks; i++)
    {
        _Static_assert(
            sizeof(sgxlkl_enclave_disk_config_t) == 328,
            "sgxlkl_enclave_disk_config_t size has changed");

        r->array[i] = mk_json_objects(NULL, 10);
        r->array[i]->objects[0] = mk_json_string("mnt", disks[i].mnt);
        r->array[i]->objects[1] =
            mk_json_hex_string("key", disks[i].key, disks[i].key_len);
        r->array[i]->objects[2] = mk_json_string("key_id", disks[i].key_id);
        r->array[i]->objects[3] =
            mk_json_boolean("fresh_key", disks[i].fresh_key);
        r->array[i]->objects[4] = mk_json_string("roothash", disks[i].roothash);
        r->array[i]->objects[5] =
            mk_json_u64("roothash_offset", disks[i].roothash_offset);
        r->array[i]->objects[6] =
            mk_json_boolean("readonly", disks[i].readonly);
        r->array[i]->objects[7] = mk_json_boolean("create", disks[i].create);
        r->array[i]->objects[8] = mk_json_u64("size", disks[i].size);
        r->array[i]->objects[9] = mk_json_boolean("overlay", disks[i].overlay);
    }
    return r;
}

static json_obj_t* mk_json_wg_peers(
    const char* key,
    const sgxlkl_enclave_wg_peer_config_t* peers,
    size_t num_peers)
{
    _Static_assert(
        sizeof(sgxlkl_enclave_wg_peer_config_t) == 24,
        "sgxlkl_enclave_wg_peer_config_t size has changed");

    json_obj_t* r = mk_json_array(key, num_peers);
    for (size_t i = 0; i < num_peers; i++)
    {
        mk_json_objects(key, 4);
        r->objects[i] = mk_json_objects(NULL, 3);
        r->objects[i]->objects[0] = mk_json_string("key", peers[i].key);
        r->objects[i]->objects[1] =
            mk_json_string("allowed_ips", peers[i].allowed_ips);
        r->objects[i]->objects[2] =
            mk_json_string("endpoint", peers[i].endpoint);
    }
    return r;
}

static json_obj_t* mk_json_wg(
    const char* key,
    const sgxlkl_enclave_wg_config_t* wg)
{
    _Static_assert(
        sizeof(sgxlkl_enclave_wg_config_t) == 40,
        "sgxlkl_enclave_wg_config_t size has changed");

    json_obj_t* r = mk_json_objects(key, 4);
    r->objects[0] = mk_json_string("ip", wg->ip);
    r->objects[1] = mk_json_u32("listen_port", wg->listen_port);
    r->objects[2] = mk_json_string("key", wg->key);
    r->objects[3] = mk_json_wg_peers("peers", wg->peers, wg->num_peers);

    return r;
}

static json_obj_t* mk_json_auxv(
    const char* key,
    const Elf64_auxv_t* auxv,
    size_t auxc)
{
    _Static_assert(sizeof(Elf64_auxv_t) == 16, "Elf64_auxv_t size has changed");

    json_obj_t* r = mk_json_array(key, auxc);
    if (auxc == 0)
        r->array = malloc(1);
    for (size_t i = 0; i < auxc; i++)
    {
        r->objects[i] = mk_json_objects(NULL, 2);
        r->objects[i]->objects[0] = mk_json_u64("a_type", auxv[i].a_type);
        r->objects[i]->objects[1] = mk_json_u64("a_val", auxv[i].a_un.a_val);
    }
    return r;
}

static json_obj_t* mk_json_image_sizes(
    char* key,
    const sgxlkl_image_sizes_config_t* sizes)
{
    _Static_assert(
        sizeof(sgxlkl_image_sizes_config_t) == 24,
        "sgxlkl_image_sizes_config_t size has changed");

    json_obj_t* r = mk_json_objects(key, 3);
    r->objects[0] = mk_json_u64("num_heap_pages", sizes->num_heap_pages);
    r->objects[1] = mk_json_u64("num_stack_pages", sizes->num_stack_pages);
    r->objects[2] = mk_json_u64("num_tcs", sizes->num_tcs);
    return r;
}

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
        sizeof(sgxlkl_enclave_config_t) == 456,
        "sgxlkl_enclave_config_t size has changed");

#define FPFBOOL(N) root->objects[cnt++] = mk_json_boolean(#N, config->N)
#define FPFS32(N) root->objects[cnt++] = mk_json_s32(#N, config->N)
#define FPFU32(N) root->objects[cnt++] = mk_json_u32(#N, config->N)
#define FPFU64(N) root->objects[cnt++] = mk_json_u64(#N, config->N)
#define FPFS(N) root->objects[cnt++] = mk_json_string(#N, config->N)
#define FPFSS(N, S) root->objects[cnt++] = mk_json_string(#N, S)

    size_t root_size =
        sizeof(sgxlkl_enclave_config_t); // way more than necessary
    json_obj_t* root = mk_json_objects(NULL, root_size);

    size_t cnt = 0;
    root->objects[cnt++] =
        mk_json_u64("format_version", SGXLKL_ENCLAVE_CONFIG_VERSION);
    FPFSS(
        mode,
        config->mode == SW_DEBUG_MODE
            ? "SW_DEBUG_MODE"
            : config->mode == HW_DEBUG_MODE
                  ? "HW_DEBUG_MODE"
                  : config->mode == HW_RELEASE_MODE ? "HW_RELEASE_MODE"
                                                    : "UNKNOWN_MODE");
    FPFU64(stacksize);
    FPFSS(
        mmap_files,
        config->mmap_files == ENCLAVE_MMAP_FILES_NONE
            ? "ENCLAVE_MMAP_FILES_NONE"
            : config->mmap_files == ENCLAVE_MMAP_FILES_SHARED
                  ? "ENCLAVE_MMAP_FILES_SHARED"
                  : config->mmap_files == ENCLAVE_MMAP_FILES_PRIVATE
                        ? "ENCLAVE_MMAP_FILES_PRIVATE"
                        : "unknown");
    FPFU64(oe_heap_pagecount);

    FPFS(net_ip4);
    FPFS(net_gw4);
    FPFS(net_mask4);
    FPFS(hostname);
    FPFU32(tap_mtu);
    FPFBOOL(hostnet);
    root->objects[cnt++] = mk_json_wg("wg", &config->wg);

    FPFU64(max_user_threads);
    FPFU64(espins);
    FPFU64(esleep);
    FPFU64(ethreads);
    root->objects[cnt++] =
        mk_json_string_clock_res("clock_res", config->clock_res);

    FPFBOOL(fsgsbase);
    FPFBOOL(verbose);
    FPFBOOL(kernel_verbose);
    FPFS(kernel_cmd);
    FPFS(sysctl);
    FPFBOOL(swiotlb);

    FPFS(cwd);
    root->objects[cnt++] =
        mk_json_string_array("args", config->args, config->num_args);
    root->objects[cnt++] =
        mk_json_string_array("envp", config->envp, config->num_envp);
    root->objects[cnt++] = mk_json_string_array(
        "host_import_envp",
        config->host_import_envp,
        config->num_host_import_envp);
    root->objects[cnt++] = mk_json_auxv("auxv", config->auxv, config->num_auxv);
    root->objects[cnt++] =
        mk_json_disks("disks", config->disks, config->num_disks);

    root->objects[cnt++] = mk_json_string(
        "exit_status",
        config->exit_status == EXIT_STATUS_FULL
            ? "EXIT_STATUS_FULL"
            : config->exit_status == EXIT_STATUS_BINARY
                  ? "EXIT_STATUS_BINARY"
                  : config->exit_status == EXIT_STATUS_NONE ? "EXIT_STATUS_NONE"
                                                            : "unknown");

    root->objects[cnt++] =
        mk_json_image_sizes("image_sizes", &config->image_sizes);

    root->size = cnt;

    sort_json(root);

    char* position = *buffer;
    print_json(buffer, buffer_size, &position, root);

    INFO("Enclave config: %s\n", *buffer);

    free_json(root);
}