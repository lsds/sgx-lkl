#include <enclave/oe_compat.h>

#ifdef SGXLKL_ENCLAVE
#include <enclave/enclave_util.h>
#define FAIL sgxlkl_fail
#define INFO sgxlkl_info
#define WARN sgxlkl_warn
#else
#include <host/sgxlkl_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FAIL sgxlkl_host_fail
#define INFO sgxlkl_host_info
#define WARN sgxlkl_host_warn
#endif

#include <errno.h>
#include <json-c/json_object.h>
#include <string.h>

#include "enclave/enclave_util.h"
#include "shared/env.h"
#include "shared/json_util.h"
#include "shared/sgxlkl_enclave_config.h"

static const char* STRING_KEYS[] = {"run",
                                    "cwd",
                                    "disk",
                                    "key",
                                    "roothash",
                                    "allowedips",
                                    "endpoint",
                                    "exit_status"};
static const char* BOOL_KEYS[] = {"readonly", "overlay", "create"};
static const char* INT_KEYS[] = {"roothash_offset", "size"};
static const char* ARRAY_KEYS[] = {"disk_config", "peers"};

static int assert_entry_type(const char* key, struct json_object* value)
{
    int err = 0;
    for (int i = 0; i < sizeof(STRING_KEYS) / sizeof(STRING_KEYS[0]); i++)
        if (!strcmp(STRING_KEYS[i], key))
            err = json_object_get_type(value) != json_type_string;

    for (int i = 0; i < sizeof(BOOL_KEYS) / sizeof(BOOL_KEYS[0]); i++)
        if (!strcmp(BOOL_KEYS[i], key))
            err = json_object_get_type(value) != json_type_boolean;

    for (int i = 0; i < sizeof(INT_KEYS) / sizeof(INT_KEYS[0]); i++)
        if (!strcmp(INT_KEYS[i], key))
            err = json_object_get_type(value) != json_type_int;

    for (int i = 0; i < sizeof(ARRAY_KEYS) / sizeof(ARRAY_KEYS[0]); i++)
        if (!strcmp(ARRAY_KEYS[i], key))
            err = json_object_get_type(value) != json_type_array;

    if (err)
        FAIL(
            "Type mismatch for '%s' configuration.\n",
            key); // TODO pass back to client.

    return err;
}

static int parse_args(sgxlkl_app_config_t* config, struct json_object* args_val)
{
    if (json_object_get_type(args_val) != json_type_array)
        return 1;

    config->argc = json_object_array_length(args_val);

    // Allocate space for argv[] + NULL element at argv[argc]
    config->argv = malloc(sizeof(char*) * (config->argc + 1));

    for (size_t i = 0; i < config->argc; i++)
    {
        json_object* val = json_object_array_get_idx(args_val, i);
        if (json_object_get_type(val) != json_type_string)
            return 1;
        config->argv[i] = strdup(json_object_get_string(val));
    }

    config->argv[config->argc] = NULL;

    return 0;
}

static int parse_env(sgxlkl_app_config_t* config, struct json_object* env_val)
{
    if (json_object_get_type(env_val) != json_type_object)
        return 1;

    int env_len = json_object_object_length(env_val);
    config->envp = malloc(sizeof(char*) * (env_len + 1));
    config->envp[env_len] = NULL;

    struct json_object_iterator it;
    const char* key;
    struct json_object* val;
    int i = 0;
    JSON_OBJECT_FOREACH(it, env_val, key, val)
    {
        if (json_object_get_type(val) != json_type_string)
            return 1;
        const char* str_val = json_object_get_string(val);
        size_t kv_len =
            strlen(key) + strlen(str_val) + 2 /* for '=' and '\0' */;
        char* env_kv = malloc(kv_len);
        if (!env_kv)
            FAIL("Failed to allocate memory for environment key value pair.\n");
        snprintf(env_kv, kv_len, "%s=%s", key, str_val);
        config->envp[i++] = env_kv;
    }

    return 0;
}

static int parse_host_import_envp(
    sgxlkl_app_config_t* config,
    struct json_object* env_val)
{
    if (json_object_get_type(env_val) != json_type_array)
        return 1;

    int len = json_object_array_length(env_val);
    config->host_import_envc = len;
    config->host_import_envp = malloc(sizeof(char*) * (len + 1));
    config->host_import_envp[len] = NULL;

    int i = 0;
    for (size_t i = 0; i < len; i++)
    {
        json_object* val = json_object_array_get_idx(env_val, i);
        if (json_object_get_type(val) != json_type_string)
            return 1;
        const char* str_val = json_object_get_string(val);
        config->host_import_envp[i++] = strdup(str_val);
    }

    return 0;
}

static int parse_enclave_disk_config_entry(
    const char* key,
    struct json_object* value,
    void* arg)
{
    int err = 0;
    sgxlkl_enclave_disk_config_t* disk = (sgxlkl_enclave_disk_config_t*)arg;

    if (assert_entry_type(key, value))
        return 1;

    if (!strcmp("disk", key))
    {
        const char* mnt_point = json_object_get_string(value);

        if (strlen(mnt_point) > SGXLKL_DISK_MNT_MAX_PATH_LEN)
            WARN("Truncating configured disk mount point...\n"); // TODO pass
                                                                 // back to
                                                                 // client.

        strncpy(disk->mnt, mnt_point, SGXLKL_DISK_MNT_MAX_PATH_LEN);
    }
    else if (!strcmp("key", key))
    {
        const char* enc_key = json_object_get_string(value);
        ssize_t key_len = hex_to_bytes(enc_key, &disk->key);
        if (key_len < 0)
            FAIL("Error parsing hex-encoded key\n");
        else
        {
            disk->key_len = key_len;
        }
    }
    else if (!strcmp("fresh_key", key))
    {
        disk->fresh_key = json_object_get_boolean(value);
    }
    else if (!strcmp("roothash", key))
    {
        disk->roothash = strdup(json_object_get_string(value));
    }
    else if (!strcmp("roothash_offset", key))
    {
        disk->roothash_offset = json_object_get_int64(value);
    }
    else if (!strcmp("readonly", key))
    {
        disk->readonly = json_object_get_boolean(value);
    }
    else if (!strcmp("overlay", key))
    {
        disk->overlay = json_object_get_boolean(value);
    }
    else if (!strcmp("create", key))
    {
        disk->create = json_object_get_boolean(value);
    }
    else if (!strcmp("size", key))
    {
        disk->size = json_object_get_int64(value);
    }
    else
    {
        FAIL("Unknown configuration entry: %s\n", key);
        return 1;
    }

    return err;
}

static int parse_disks(
    sgxlkl_app_config_t* config,
    struct json_object* disks_val)
{
    if (json_object_get_type(disks_val) != json_type_array)
        return 1;

    int num_disks = json_object_array_length(disks_val);
    sgxlkl_enclave_disk_config_t* disks =
        malloc(sizeof(sgxlkl_enclave_disk_config_t) * num_disks);
    memset(disks, 0, sizeof(sgxlkl_enclave_disk_config_t) * num_disks);

    int i, j, ret;
    for (i = 0; i < num_disks; i++)
    {
        json_object* val = json_object_array_get_idx(disks_val, i);
        ret = parse_json(val, parse_enclave_disk_config_entry, &disks[i]);
        if (ret)
        {
            for (j = 0; j <= i; j++)
            {
                free(disks[j].key);
                free(disks[j].key_id);
                free(disks[j].roothash);
            }
            free(disks);
            return ret;
        }
    }

    config->num_disks = num_disks;
    config->disks = disks;

    return 0;
}

static int parse_enclave_wg_peer_config_entry(
    const char* key,
    struct json_object* value,
    void* arg)
{
    int err = 0;
    sgxlkl_enclave_wg_peer_config_t* peer =
        (sgxlkl_enclave_wg_peer_config_t*)arg;

    if (assert_entry_type(key, value))
        return 1;

    if (!strcmp("key", key))
    {
        peer->key = strdup(json_object_get_string(value));
    }
    else if (!strcmp("allowedips", key))
    {
        peer->allowed_ips = strdup(json_object_get_string(value));
    }
    else if (!strcmp("endpoint", key))
    {
        peer->endpoint = strdup(json_object_get_string(value));
    }
    else
    {
        FAIL("Unknown configuration entry: %s\n", key);
        return 1;
    }

    return err;
}

static int parse_network(
    sgxlkl_app_config_t* config,
    struct json_object* net_val)
{
    if (json_object_get_type(net_val) != json_type_object)
        return 1;

    struct json_object_iterator it;
    const char* key;
    struct json_object* value;
    JSON_OBJECT_FOREACH(it, net_val, key, value)
    {
        // For now, the only acceptable field is 'peers' which is expected to
        // contain an array of wireguard peer configurations.
        if (strcmp(key, "peers"))
            continue;
        if (assert_entry_type(key, value))
            return 1;

        int num_peers = json_object_array_length(value);
        sgxlkl_enclave_wg_peer_config_t* peers =
            malloc(sizeof(sgxlkl_enclave_wg_peer_config_t) * num_peers);
        memset(peers, 0, sizeof(sgxlkl_enclave_wg_peer_config_t) * num_peers);

        int i, j, ret;
        for (i = 0; i < num_peers; i++)
        {
            json_object* val = json_object_array_get_idx(value, i);
            ret =
                parse_json(val, parse_enclave_wg_peer_config_entry, &peers[i]);
            if (ret)
            {
                for (j = 0; j <= i; j++)
                {
                    if (peers[j].key)
                        free(peers[j].key);
                    if (peers[j].allowed_ips)
                        free(peers[j].allowed_ips);
                    if (peers[j].endpoint)
                        free(peers[j].endpoint);
                }
                free(peers);
                return ret;
            }
        }

        config->num_peers = num_peers;
        config->peers = peers;

        break;
    }

    return 0;
}

static uint64_t parse_uint64(const char* key, struct json_object* value)
{
    if (json_object_get_type(value) == json_type_string)
    {
        const char* vstr = json_object_get_string(value);
        uint64_t r = strtoul(vstr, NULL, 10);
        if (r == UINT64_MAX && errno == ERANGE)
            FAIL("Invalid configuration entry for %s: %s\n", key, vstr);
        return r;
    }
    else if (json_object_get_type(value) == json_type_int)
    {
        int64_t r = json_object_get_int64(value);
        if (r < 0)
            FAIL("Invalid uint64 value for '%s'\n", key);
        return r;
    }
    else
        FAIL("Invalid uint64 value for '%s'\n", key);
}

static int parse_sizes(
    sgxlkl_app_config_t* config,
    struct json_object* sizes_val)
{
    if (json_object_get_type(sizes_val) != json_type_object)
        return 1;

    struct json_object_iterator it;
    const char* key;
    struct json_object* value;
    JSON_OBJECT_FOREACH(it, sizes_val, key, value)
    {
        if (!strcmp("num_heap_pages", key))
            config->sizes.num_heap_pages = parse_uint64(key, value);
        else if (!strcmp("num_stack_pages", key))
            config->sizes.num_stack_pages = parse_uint64(key, value);
        else if (!strcmp("num_tcs", key))
            config->sizes.num_tcs = parse_uint64(key, value);
        else
        {
            FAIL("Unknown configuration entry: %s\n", key);
            return 1;
        }
    }

    return 0;
}

static int parse_sgxlkl_app_config_entry(
    const char* key,
    struct json_object* value,
    void* arg)
{
    int err = 0;
    sgxlkl_app_config_t* config = (sgxlkl_app_config_t*)arg;

    if (!strcmp("run", key))
    {
        if (json_object_get_type(value) != json_type_string)
        {
            FAIL("String expected for 'run' configuration.\n");
            return 1;
        }
        config->run = strdup(json_object_get_string(value));
    }
    else if (!strcmp("cwd", key))
    {
        if (json_object_get_type(value) != json_type_string)
        {
            FAIL("String expected for 'cwd' configuration.\n");
            return 1;
        }
        config->cwd = strdup(json_object_get_string(value));
    }
    else if (!strcmp("args", key))
    {
        err = parse_args(config, value);
    }
    else if (!strcmp("environment", key))
    {
        err = parse_env(config, value);
    }
    else if (!strcmp("host_import_envp", key))
    {
        err = parse_host_import_envp(config, value);
    }
    else if (!strcmp("exit_status", key))
    {
        if (json_object_get_type(value) != json_type_string)
        {
            FAIL("Appconfig error: String expected for 'exit_status'.\n");
        }

        if (!strcmp("full", json_object_get_string(value)))
        {
            config->exit_status = EXIT_STATUS_FULL;
        }
        else if (!strcmp("binary", json_object_get_string(value)))
        {
            config->exit_status = EXIT_STATUS_BINARY;
        }
        else if (!strcmp("none", json_object_get_string(value)))
        {
            config->exit_status = EXIT_STATUS_NONE;
        }
        else
        {
            FAIL("Appconfig error: Value for 'exit_status' must be "
                 "\"full\"|\"binary\"|\"none\".\n");
        }
    }
    else if (!strcmp("disk_config", key))
    {
        err = parse_disks(config, value);
    }
    else if (!strcmp("network_config", key))
    {
        err = parse_network(config, value);
    }
    else if (!strcmp("$schema", key))
    {
        // ignore
    }
    else if (!strcmp("sizes", key))
    {
        err = parse_sizes(config, value);
    }
    else
    {
        FAIL("Unknown configuration entry: %s\n", key);
        return 1;
    }
    return err;
}

/* Function to parse the json schema recieved from remote server. If a parsing
 * error occurs, err will be set to a pointer to an error description and to
 * NULL otherwise. */
int parse_sgxlkl_app_config_from_str(
    const char* str,
    sgxlkl_app_config_t* config,
    char** err)
{
    *err = NULL;
    int res = 0;

    res = parse_json_from_str(str, parse_sgxlkl_app_config_entry, config, err);
    if (res)
    {
        if (!*err)
            *err = strdup("Unexpected application configuration format");
    }

    return res;
}