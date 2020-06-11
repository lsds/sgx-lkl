#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_util.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "shared/json_util.h"

#define MALFORMED_JSON_ERR "Unexpected character '%c', '{' expected."

static int validate_json_str(const char* str, char** err)
{
    // JSON-C segfaults with malformed JSON that doesn't start with '{'. Detect
    // here
    const char* c = str;

    while (isspace(*c))
        c++;

    if (*c != '{')
    {
        if (err)
        {
            char* errmsg = malloc(strlen(MALFORMED_JSON_ERR) + 1);
            snprintf(
                errmsg, strlen(MALFORMED_JSON_ERR) + 1, MALFORMED_JSON_ERR, *c);
            *err = errmsg;
        }
        else
            fprintf(
                stderr,
                "Failed to parse config: Unexpected character '%c','{' "
                "expected.",
                *c);
        return -1;
    }
    return 0;
}

static int parse_json_by_key(
    struct json_object* jobj,
    const char* key_str,
    json_type type,
    char** userarg)
{
    struct json_object_iterator it;
    const char* key;
    struct json_object* value;
    char** data = NULL;
    JSON_OBJECT_FOREACH(it, jobj, key, value)
    {
        if (strcmp(key_str, key))
            continue;

        switch (json_object_get_type(value))
        {
            case json_type_string:
                data = userarg;
                *data = strdup(json_object_get_string(value));
                break;
            case json_type_object:
                data = userarg;
                *data = strdup(json_object_get_string(value));
                break;
            default:
                fprintf(
                    stderr,
                    "other than string json type request, check other API \n");
                return -1;
        }
    }
    return 0;
}

int parse_json(struct json_object* jobj, parse_json_callback cb, void* userarg)
{
    struct json_object_iterator it;
    const char* key;
    struct json_object* value;
    JSON_OBJECT_FOREACH(it, jobj, key, value)
    {
        int retval = cb(key, value, userarg);
        if (retval != 0)
        {
            return retval;
        }
    }
    return 0;
}

/*
If a JSON parsing error occurs, err will be set to a pointer to an error
description. If the provided callback returns a non-zero return value, -1 will
be returned, and *err will be set to NULL (if err provided).
*/
int parse_json_from_str(
    const char* str,
    parse_json_callback cb,
    void* userarg,
    char** err)
{
    int ret = 0;
    struct json_object* jobj;
    enum json_tokener_error error = json_tokener_success;

    ret = validate_json_str(str, err);
    if (ret)
        return ret;

    jobj = json_tokener_parse_verbose(str, &error);
    if (!jobj)
    {
        if (err)
            *err = strdup(json_tokener_error_desc(error));
        else
            fprintf(
                stderr,
                "Failed to parse config: %s\n",
                json_tokener_error_desc(error));
        return -1;
    }

    // requires json-c 13.x
    if (parse_json(jobj, cb, userarg))
    {
        if (err)
            *err = NULL;
        ret = -1;
    }

    // Decrement reference count on jobj and free memory
    json_object_put(jobj);

    return ret;
}

/*
If a JSON parsing error occurs, err will be set to a pointer to an error
description. If the provided callback returns a non-zero return value, -1 will
be returned, and *err will be set to NULL (if err provided).
*/
int get_string_value_from_json_str(
    const char* str,
    const char* key,
    char** value,
    char** err)
{
    int ret = 0;
    struct json_object* jobj;
    enum json_tokener_error error = json_tokener_success;

    ret = validate_json_str(str, err);
    if (ret)
        return ret;

    jobj = json_tokener_parse_verbose(str, &error);
    if (!jobj)
    {
        if (err)
            *err = strdup(json_tokener_error_desc(error));
        else
            fprintf(
                stderr,
                "Failed to parse config: %s\n",
                json_tokener_error_desc(error));
        return -1;
    }

    if (parse_json_by_key(jobj, key, json_type_string, value))
    {
        if (err)
            *err = NULL;
        ret = -1;
    }
    json_object_put(jobj);

    return ret;
}

// TODO Return error description in err.
int parse_json_from_file(
    char* path,
    parse_json_callback cb,
    void* userarg,
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
            *err = strdup("Failed to alloate memory for JSON buffer");
        else
            perror("Failed to alloate memory for JSON buffer");
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

    int res = parse_json_from_str(buf, cb, userarg, err);
    free(buf);
    return res;
}
