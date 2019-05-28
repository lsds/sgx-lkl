#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <json-c/json_util.h>
#include <json-c/json_object_iterator.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "json_util.h"

#define MALFORMED_JSON_ERR "Unexpected character '%c', '{' expected."

int parse_json(struct json_object *jobj, parse_json_callback cb, void *userarg) {
    struct json_object_iterator it;
    const char* key;
    struct json_object* value;
    JSON_OBJECT_FOREACH(it, jobj, key, value) {
        //printf("%s\n", key);
        int retval = cb(key, value, userarg);
        if (retval != 0) {
            return retval;
        }
    }
}

int parse_json_from_str(char *str, parse_json_callback cb, void *userarg, char **err) {
    struct json_object *jobj;
    enum json_tokener_error error = json_tokener_success;

    // JSON-C segfaults with malformed JSON that doesn't start with '{'. Detect
    // here.
    char *c = str;
    while (isspace(*c)) c++;
    if (*c != '{') {
        if (err) {
            char *errmsg = malloc(strlen(MALFORMED_JSON_ERR) + 1);
            snprintf(errmsg, strlen(MALFORMED_JSON_ERR) + 1, MALFORMED_JSON_ERR, *c);
            *err = errmsg;
        } else
            fprintf(stderr, "Failed to parse config: Unexpected character '%c', '{' expected.", *c);
        return -1;
    }

    jobj = json_tokener_parse_verbose(str, &error);
    if(!jobj) {
        if (err)
            *err = strdup(json_tokener_error_desc(error));
        else
            fprintf(stderr, "Failed to parse config: %s\n", json_tokener_error_desc(error));
        return -1;
    }

    // requires json-c 13.x
    //int rv;
    //rv = json_c_visit(jobj, 0, parse, null);

    parse_json(jobj, cb, userarg);

    // Decrement reference count on jobj and free memory
    json_object_put(jobj);

    return 0;
}

// TODO Return error description in err.
int parse_json_from_file(char *path, parse_json_callback cb, void *userarg, char **err) {
    int fd;
    if ((fd = open(path, O_RDONLY)) < 0) {
        if (err)
            *err = strdup(strerror(errno));
        else
            perror("Failed to open JSON file");
        return -1;
    }

    off_t len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char *buf = (char *) malloc(len + 1);
    ssize_t ret;
    int off = 0;
    while ((ret = read(fd, &buf[off], len - off)) > 0) {
        off += ret;
    }
    buf[len] = 0;

    close(fd);

    if (ret < 0) {
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
