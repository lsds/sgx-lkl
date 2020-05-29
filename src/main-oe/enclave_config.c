#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "enclave/enclave_mem.h"
#include "host/sgxlkl_util.h"
#include "shared/sgxlkl_app_config.h"
#include "shared/sgxlkl_config.h"
#include "shared/sgxlkl_config_json.h"

#include "shared/enclave_config.h"

#define FAIL sgxlkl_host_fail
#define INFO sgxlkl_host_info

typedef struct json_obj
{
    char* key;
    char* value;
    struct json_obj** array;
    struct json_obj** objects;
    size_t size;
} json_obj_t;

static json_obj_t* mk_json_obj(
    const char* key,
    const char* value,
    json_obj_t** array,
    json_obj_t** objects,
    size_t size)
{
    json_obj_t* r = calloc(1, sizeof(json_obj_t));
    if (!r)
        FAIL("out of memory\n");
    if (key)
        r->key = strdup(key);
    if (value)
        r->value = strdup(value);
    r->array = array;
    r->objects = objects;
    r->size = size;
    return r;
}

static json_obj_t* mk_json_string(const char* key, const char* value)
{
    return mk_json_obj(key, value, NULL, NULL, 0);
}

static json_obj_t* mk_json_array(const char* key, size_t len)
{
    json_obj_t* r = mk_json_obj(key, NULL, NULL, NULL, len);
    r->array = calloc(len, sizeof(char*));
    if (!r->array)
        FAIL("out of memory\n");
    return r;
}

static json_obj_t* mk_json_objects(const char* key, size_t len)
{
    json_obj_t* r = mk_json_obj(key, NULL, NULL, NULL, len);
    r->objects = calloc(len, sizeof(json_obj_t*));
    if (!r->objects)
        FAIL("out of memory\n");
    return r;
}

static json_obj_t* mk_json_x16(const char* key, uint32_t value)
{
    char* tmp = calloc(1, 4 * 2 + 1);
    if (!tmp)
        FAIL("out of memory\n");
    snprintf(tmp, sizeof(tmp), "%" PRIx16, value);
    return mk_json_string(key, tmp);
}

static json_obj_t* mk_json_x32(const char* key, uint32_t value)
{
    char* tmp = calloc(1, 4 * 2 + 1);
    if (!tmp)
        FAIL("out of memory\n");
    snprintf(tmp, sizeof(tmp), "%" PRIx32, value);
    return mk_json_string(key, tmp);
}

static json_obj_t* mk_json_x64(const char* key, uint64_t value)
{
    char* tmp = calloc(1, 8 * 2 + 1);
    if (!tmp)
        FAIL("out of memory\n");
    snprintf(tmp, sizeof(tmp), "%" PRIx64, value);
    return mk_json_string(key, tmp);
}

static json_obj_t* mk_json_string_array(
    const char* key,
    char* const* strings,
    size_t num_strings)
{
    json_obj_t* res = mk_json_array(key, num_strings);
    for (size_t i = 0; i < num_strings; i++)
        res->array[i] = mk_json_string(NULL, strings[i]);
    return res;
}

static json_obj_t* mk_json_string_clock_res(
    const char* key,
    const struct timespec clock_res[8])
{
    json_obj_t* res = mk_json_array(key, 8);
    char tmp[8 * 2 * 2 + 1];
    for (size_t i = 0; i < 8; i++)
    {
        snprintf(
            tmp,
            sizeof(tmp),
            "%08lx%08lx",
            clock_res[i].tv_sec,
            clock_res[i].tv_nsec);
        res->array[i] = mk_json_string(NULL, tmp);
    }
    return res;
}

static json_obj_t* mk_json_disks(
    const char* key,
    enclave_disk_config_t* disks,
    size_t num_disks)
{
    json_obj_t* r = mk_json_array(key, num_disks);
    for (size_t i = 0; i < num_disks; i++)
    {
        _Static_assert(
            sizeof(enclave_disk_config_t) == 352,
            "enclave_disk_config_t size has changed");
        r->array[i] = mk_json_objects(NULL, 3);
        r->array[i]->objects[0] = mk_json_x32("create", disks[i].create);
        r->array[i]->objects[1] = mk_json_x64("size", disks[i].size);
        // r->array[i]->objects[2] = mk_json_x32("enc", disks[i].enc);
        r->array[i]->objects[2] = mk_json_string("mnt", disks[i].mnt);
    }
    return r;
}

static json_obj_t* mk_json_app_disks(
    const char* key,
    sgxlkl_app_disk_config_t* disks,
    size_t num_disks)
{
    json_obj_t* r = mk_json_array(key, num_disks);
    for (size_t i = 0; i < num_disks; i++)
    {
        _Static_assert(
            sizeof(sgxlkl_app_disk_config_t) == 312,
            "sgxlkl_app_disk_config_t size has changed");

        r->array[i] = mk_json_objects(NULL, 9);
        r->array[i]->objects[0] = mk_json_string("mnt", disks[i].mnt);
        r->array[i]->objects[1] = mk_json_string("key", disks[i].key);
        r->array[i]->objects[2] = mk_json_string("key_id", disks[i].key_id);
        r->array[i]->objects[3] = mk_json_x64("key_len", disks[i].key_len);
        r->array[i]->objects[4] = mk_json_string("roothash", disks[i].roothash);
        r->array[i]->objects[5] =
            mk_json_x64("roothash_offset", disks[i].roothash_offset);
        r->array[i]->objects[6] = mk_json_x32("readonly", disks[i].readonly);
        r->array[i]->objects[7] = mk_json_x32("create", disks[i].create);
        r->array[i]->objects[8] = mk_json_x64("size", disks[i].size);
    }
    return r;
}

static json_obj_t* mk_json_wg_peers(
    const char* key,
    const enclave_wg_peer_config_t* peers,
    size_t num_peers)
{
    _Static_assert(
        sizeof(enclave_wg_peer_config_t) == 24,
        "enclave_wg_peer_config_t size has changed");

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

static json_obj_t* mk_json_wg(const char* key, const enclave_wg_config_t* wg)
{
    _Static_assert(
        sizeof(enclave_wg_config_t) == 32,
        "enclave_wg_config_t size has changed");

    json_obj_t* r = mk_json_objects(key, 4);
    r->objects[0] = mk_json_x32("ip", wg->ip);
    r->objects[1] = mk_json_x16("listen_port", wg->listen_port);
    r->objects[2] = mk_json_string("key", wg->key);
    r->objects[3] = mk_json_wg_peers("peers", wg->peers, wg->num_peers);

    return r;
}

static json_obj_t* mk_json_auxv(const char* key, const Elf64_auxv_t* auxv)
{
    _Static_assert(sizeof(Elf64_auxv_t) == 16, "Elf64_auxv_t size has changed");

    size_t auxc = 0;
    for (const Elf64_auxv_t* p = auxv; p && p->a_type != AT_NULL; p++)
        auxc++;

    json_obj_t* r = mk_json_array(key, auxc);
    for (size_t i = 0; i < auxc; i++)
    {
        r->objects[i] = mk_json_objects(NULL, 2);
        r->objects[i]->objects[0] = mk_json_x64("a_type", auxv->a_type);
        r->objects[i]->objects[1] = mk_json_x64("a_val", auxv->a_un.a_val);
    }
    return r;
}

static json_obj_t* mk_json_app_config(const char* app_config_str)
{
    if (!app_config_str)
        return mk_json_obj("app_config", NULL, NULL, NULL, 0);

    size_t len = strlen(app_config_str) + 32;
    char tmp[len];
    snprintf(tmp, len, "{\"app_config\":%s}", app_config_str);

    sgxlkl_app_config_t app_config = {0};
    char* err = NULL;
    if (parse_sgxlkl_app_config_from_str(app_config_str, &app_config, &err))
        FAIL("%s\n", err);
    if (validate_sgxlkl_app_config(&app_config))
        FAIL("app config validation failed\n", err);

    json_obj_t* r = mk_json_objects("app_config", 7);
    r->objects[0] = mk_json_string("run", app_config.run);
    r->objects[1] = mk_json_string("cwd", app_config.cwd);
    r->objects[2] =
        mk_json_string_array("argv", app_config.argv, app_config.argc);
    r->objects[3] =
        mk_json_string_array("envp", app_config.envp, app_config.envc);
    r->objects[4] =
        mk_json_app_disks("disks", app_config.disks, app_config.num_disks);
    r->objects[5] =
        mk_json_wg_peers("peers", app_config.peers, app_config.num_peers);
    switch (app_config.exit_status)
    {
        case EXIT_STATUS_FULL:
            r->objects[6] = mk_json_string("exit_status", "full");
        case EXIT_STATUS_BINARY:
            r->objects[6] = mk_json_string("exit_status", "binary");
        case EXIT_STATUS_NONE:
            r->objects[6] = mk_json_string("exit_status", "none");
        default:
            r->objects[6] = mk_json_string("exit_status", "unknown");
    }
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

    if (obj->value)
    {
        print_to_buffer(buffer, buffer_size, position, "\"");

        char* val_copy = strdup(obj->value);
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
    else
        print_to_buffer(buffer, buffer_size, position, "null");
}

static void free_json(json_obj_t* obj)
{
    if (obj)
    {
        free(obj->key);
        free(obj->value);
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
    return !obj->value && !obj->array && obj->objects;
}

static bool is_json_array(const json_obj_t* obj)
{
    return !obj->value && obj->array && !obj->objects;
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
    else if (is_json_array)
    {
        for (size_t i = 0; i < obj->size; i++)
            sort_json(obj->array[i]);
    }
}

void compose_enclave_config(
    const sgxlkl_config_t* config,
    char** buffer,
    size_t* buffer_size,
    const char* filename)
{
    if (!buffer || !buffer_size)
        FAIL("no buffer for config");

    // Catch modifications to sgxlkl_config_t early.
    _Static_assert(
        sizeof(sgxlkl_config_t) == 472, "sgxlkl_config_t size has changed");

#define FPF32(N) root->objects[cnt++] = mk_json_x32(#N, config->N)
#define FPF64(N) root->objects[cnt++] = mk_json_x64(#N, config->N)
#define FPFS(N) root->objects[cnt++] = mk_json_string(#N, config->N)
#define FPFSS(N, S) root->objects[cnt++] = mk_json_string(#N, S)

    size_t root_size = sizeof(sgxlkl_config_t); // way more than necessary
    json_obj_t* root = mk_json_objects(NULL, root_size);

    size_t cnt = 0;
    FPF64(max_user_threads);
    FPF64(stacksize);
    root->objects[cnt++] =
        mk_json_disks("disks", config->disks, config->num_disks);
    FPFSS(
        mmap_files,
        config->mmap_files == ENCLAVE_MMAP_FILES_NONE
            ? "none"
            : config->mmap_files == ENCLAVE_MMAP_FILES_SHARED
                  ? "shared"
                  : config->mmap_files == ENCLAVE_MMAP_FILES_PRIVATE
                        ? "private"
                        : "unknown");
    FPF32(net_fd);
    FPF32(oe_heap_pagecount);
    FPF32(net_ip4);
    FPF32(net_gw4);
    FPF32(net_mask4);
    FPFS(hostname);
    FPF32(hostnet);
    FPF32(tap_offload);
    FPF32(tap_mtu);
    root->objects[cnt++] = mk_json_wg("wg", &config->wg);
    root->objects[cnt++] =
        mk_json_string_array("argv", config->argv, config->argc);
    char* const* envp = config->argv + config->argc;
    size_t envc = 0;
    for (char* const* p = envp; *p != NULL; p++)
        envc++;
    root->objects[cnt++] = mk_json_string_array("envp", envp, envc);
    root->objects[cnt++] = mk_json_auxv("auxv", config->auxv);
    FPFS(cwd);
    FPFSS(
        exit_status,
        config->exit_status == EXIT_STATUS_FULL
            ? "full"
            : config->exit_status == EXIT_STATUS_BINARY
                  ? "binary"
                  : config->exit_status == EXIT_STATUS_NONE ? "none"
                                                            : "unknown");
    FPF64(espins);
    FPF64(esleep);
    FPF64(sysconf_nproc_conf);
    FPF64(sysconf_nproc_onln);
    root->objects[cnt++] =
        mk_json_string_clock_res("clock_res", config->clock_res);
    FPF32(mode);
    FPF32(fsgsbase);
    FPF32(verbose);
    FPF32(kernel_verbose);
    FPFS(kernel_cmd);
    FPFS(sysctl);

    root->objects[cnt++] = mk_json_app_config(config->app_config_str);

    root->size = cnt;

    sort_json(root);

    char* position = *buffer;
    print_json(buffer, buffer_size, &position, root);

    if (filename)
    {
        FILE* f = fopen(filename, "w");
        if (!f)
            FAIL("error opening '%s'\n", filename);
        fwrite(*buffer, 1, position - *buffer, f);
        fclose(f);
    }

    free_json(root);
}