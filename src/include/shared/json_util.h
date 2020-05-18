#ifndef JSON_UTIL_H
#define JSON_UTIL_H

#include <json-c/json.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_util.h>

#define JSON_OBJECT_FOREACH(it, obj, key, value)              \
    for ((it) = json_object_iter_begin(obj);                  \
         (it).opaque_ != json_object_iter_end(obj).opaque_ && \
         ((key) = json_object_iter_peek_name(&(it))) &&       \
         ((value) = json_object_iter_peek_value(&(it)));      \
         json_object_iter_next(&(it)))

typedef int (*parse_json_callback)(const char*, struct json_object*, void*);

int my_callback(const char* key, struct json_object* value, void* userarg);

int parse_json(struct json_object* jobj, parse_json_callback cb, void* userarg);

int parse_json_from_str(
    const char* str,
    parse_json_callback cb,
    void* userarg,
    char** err);

int parse_json_from_file(
    char* path,
    parse_json_callback cb,
    void* userarg,
    char** err);

int get_string_value_from_json_str(
    const char* str,
    const char* key,
    char** data,
    char** err);

#endif /* JSON_UTIL_H */
