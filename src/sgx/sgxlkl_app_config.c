#include <errno.h>
#include <json-c/json_object.h>
#include <stdio.h>
#include <string.h>

#include "json_util.h"
#include "sgx_enclave_config.h"
#include "sgxlkl_app_config.h"
#include "sgxlkl_util.h"

static const char* STRING_KEYS[] = {"run", "disk", "key", "roothash", "allowedips", "endpoint"};
static const char* BOOL_KEYS[] = {"readonly"};
static const char* INT_KEYS[] = {"roothash_offset"};
static const char* ARRAY_KEYS[] = {"disk_config", "peers"};

static int assert_entry_type(const char *key, struct json_object *value) {
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
        fprintf(stderr, "Type mismatch for '%s' configuration.\n", key); // TODO pass back to client.

    return err;
}

static int parse_args(sgxlkl_app_config_t *config, struct json_object *args_val) {
    if (json_object_get_type(args_val) != json_type_array)
        return 1;

    config->argc = json_object_array_length(args_val) + 1; // Reserve argv[0]
    config->argv = malloc(sizeof(char*) * (config->argc + 1)); // Allocate space for argv[] + NULL element at argv[argc]
    int i;
    for (i = 1; i < config->argc; i++) {
        json_object *val = json_object_array_get_idx(args_val, i - 1);
        if (json_object_get_type(val) != json_type_string)
            return 1;
        config->argv[i] = strdup(json_object_get_string(val));
    }

    config->argv[config->argc] = NULL;

    return 0;
}

static int parse_env(sgxlkl_app_config_t *config, struct json_object *env_val) {
    if (json_object_get_type(env_val) != json_type_object)
        return 1;

    int env_len = json_object_object_length(env_val);
    config->envp = malloc(sizeof(char*) * (env_len + 1));
    config->envp[env_len] = NULL;

    struct json_object_iterator it;
    const char* key;
    struct json_object* val;
    int i = 0;
    JSON_OBJECT_FOREACH(it, env_val, key, val) {
        if (json_object_get_type(val) != json_type_string)
            return 1;
        const char *str_val = json_object_get_string(val);
        size_t kv_len = strlen(key) +  strlen(str_val) + 2 /* for '=' and '\0' */;
        char *env_kv = malloc(kv_len);
        if (!env_kv)
            sgxlkl_fail("Failed to allocate memory for environment key value pair.\n");
        snprintf(env_kv, kv_len, "%s=%s", key, str_val);
        config->envp[i++] = env_kv;
    }

    return 0;
}

static int parse_enclave_disk_config_entry(const char *key, struct json_object *value, void *arg) {
    int err = 0;
    enclave_disk_config_t *disk = (enclave_disk_config_t *)arg;

    if (assert_entry_type(key, value))
        return 1;

    if (!strcmp("disk", key)) {
        const char *mnt_point = json_object_get_string(value);
        if (strlen(mnt_point) > SGXLKL_DISK_MNT_MAX_PATH_LEN)
            sgxlkl_warn("Truncating configured disk mount point...\n"); // TODO pass back to client.
        strncpy(disk->mnt, mnt_point, SGXLKL_DISK_MNT_MAX_PATH_LEN);
    } else if (!strcmp("key", key)) {
        const char *enc_key = json_object_get_string(value);
        disk->key_len = hex_to_bytes(enc_key, &disk->key);
        if (disk->key_len < 0)
            err = disk->key_len;
        else
            disk->enc = 1;
    } else if (!strcmp("roothash", key)) {
        disk->roothash = strdup(json_object_get_string(value));
    } else if (!strcmp("roothash_offset", key)) {
        disk->roothash_offset = json_object_get_int64(value);
    } else if (!strcmp("readonly", key)) {
        disk->ro = json_object_get_boolean(value);
    } else {
        fprintf(stderr, "Unknown configuration entry: %s\n", key);
        return 1;
    }

    return err;
}

static int parse_disks(sgxlkl_app_config_t *config, struct json_object *disks_val) {
    if (json_object_get_type(disks_val) != json_type_array)
        return 1;

    int num_disks = json_object_array_length(disks_val);
    enclave_disk_config_t *disks = malloc(sizeof(enclave_disk_config_t) * num_disks);
    memset(disks, 0, sizeof(enclave_disk_config_t) * num_disks);

    int i, j, ret;
    for (i = 0; i < num_disks; i++){
        json_object *val = json_object_array_get_idx(disks_val, i);
        ret = parse_json(val, parse_enclave_disk_config_entry, &disks[i]);
        if (ret) {
            for (j = 0; j <= i; j++) {
                if (disks[j].key) free(disks[j].key);
                if (disks[j].roothash) free(disks[j].roothash);
            }
            free(disks);
            return ret;
        }
    }

    config->num_disks = num_disks;
    config->disks = disks;

    return 0;
}

static int parse_enclave_wg_peer_config_entry(const char *key, struct json_object *value, void *arg) {
    int err = 0;
    enclave_wg_peer_config_t *peer = (enclave_wg_peer_config_t *)arg;

    if (assert_entry_type(key, value))
        return 1;

    if (!strcmp("key", key)) {
        peer->key = strdup(json_object_get_string(value));
    } else if (!strcmp("allowedips", key)) {
        peer->allowed_ips = strdup(json_object_get_string(value));
    } else if (!strcmp("endpoint", key)) {
        peer->endpoint = strdup(json_object_get_string(value));
    } else {
        fprintf(stderr, "Unknown configuration entry: %s\n", key);
        return 1;
    }

    return err;
}

static int parse_network(sgxlkl_app_config_t *config, struct json_object *net_val) {
    if (json_object_get_type(net_val) != json_type_object)
        return 1;

    struct json_object_iterator it;
    const char* key;
    struct json_object* value;
    JSON_OBJECT_FOREACH(it, net_val, key, value) {
        // For now, the only acceptable field is 'peers' which is expected to
        // contain an array of wireguard peer configurations.
        if (strcmp(key, "peers")) continue;
        if (assert_entry_type(key, value)) return 1;

        int num_peers = json_object_array_length(value);
        enclave_wg_peer_config_t *peers = malloc(sizeof(enclave_wg_peer_config_t) * num_peers);
        memset(peers, 0, sizeof(enclave_wg_peer_config_t) * num_peers);

        int i, j, ret;
        for (i = 0; i < num_peers; i++){
            json_object *val = json_object_array_get_idx(value, i);
            ret = parse_json(val, parse_enclave_wg_peer_config_entry, &peers[i]);
            if (ret) {
                for (j = 0; j <= i; j++) {
                    if (peers[j].key) free(peers[j].key);
                    if (peers[j].allowed_ips) free(peers[j].allowed_ips);
                    if (peers[j].endpoint) free(peers[j].endpoint);
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

static int parse_sgxlkl_app_config_entry(const char *key, struct json_object *value, void *arg) {
    int err = 0;
    sgxlkl_app_config_t *config = (sgxlkl_app_config_t *)arg;

    if (!strcmp("run", key)) {
        if (json_object_get_type(value) != json_type_string) {
            fprintf(stderr, "String expected for 'run' configuration.\n");
            return 1;
        }
        config->run = strdup(json_object_get_string(value));
    } else if (!strcmp("args", key)) {
        err = parse_args(config, value);
    } else if (!strcmp("environment", key)) {
        err = parse_env(config, value);
    } else if (!strcmp("disk_config", key)) {
        err = parse_disks(config, value);
    } else if (!strcmp("network_config", key)) {
        err = parse_network(config, value);
    } else {
        fprintf(stderr, "Unknown configuration entry: %s\n", key);
        return 1;
    }
    return err;
}

/*
If a parsing error occurs, err will be set to a pointer to an error description
and to NULL otherwise.
*/
int parse_sgxlkl_app_config_from_str(char *str, sgxlkl_app_config_t *config, char **err) {
    *err = NULL;
    int res = parse_json_from_str(str, parse_sgxlkl_app_config_entry, config, err);
    if (res) {
        if (!*err)
            *err = strdup("Unexpected application configuration format");
        return res;
    }

    if (!config->run) {
        *err = "No executable path provided via 'run'.";
        return 1;
    }

    if (!config->argv) {
        if (!(config->argv = malloc(sizeof(config->argv) * 2)))
            sgxlkl_fail("Failed to allocate memory for app config argv: %s\n", strerror(errno));
        config->argc = 1;
        config->argv[1] = NULL;
    }

    if (!config->envp) {
        if (!(config->envp = malloc(sizeof(config->envp))))
            sgxlkl_fail("Failed to allocate memory for app config envp: %s\n", strerror(errno));
        config->envp[0] = NULL;
    }

    // Fix argv[0]
    config->argv[0] = config->run;

    return 0;
}
