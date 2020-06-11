/*
**==============================================================================
**
** Copyright (c) Microsoft Corporation
**
** All rights reserved.
**
** MIT License
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the ""Software""), to
** deal in the Software without restriction, including without limitation the
** rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
** sell copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions: The above copyright
** notice and this permission notice shall be included in all copies or
** substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
**==============================================================================
*/

#ifndef _JSON_H
#define _JSON_H

typedef unsigned long size_t;
typedef unsigned long uint64_t;
typedef long int64_t;

#define JSON_MAX_NESTING 64

typedef enum _json_result
{
    JSON_OK,
    JSON_FAILED,
    JSON_EOF,
    JSON_BAD_SYNTAX,
    JSON_UNSUPPORTED,
    JSON_BAD_PARAMETER,
    JSON_UNEXPECTED,
    JSON_OUT_OF_MEMORY,
    JSON_TYPE_MISMATCH,
    JSON_NESTING_OVERFLOW,
    JSON_NESTING_UNDERFLOW,
    JSON_BUFFER_OVERFLOW,
    JSON_UNKNOWN_VALUE,
    JSON_OUT_OF_BOUNDS,
    JSON_NO_MATCH,
}
json_result_t;

typedef enum _json_type
{
    JSON_TYPE_NULL,
    JSON_TYPE_BOOLEAN,
    JSON_TYPE_INTEGER,
    JSON_TYPE_REAL,
    JSON_TYPE_STRING,
}
json_type_t;

const char* json_result_string(json_result_t result);

typedef union _json_union
{
    unsigned char boolean;
    int64_t integer;
    double real;
    char* string;
}
json_union_t;

typedef enum _json_reason
{
    JSON_REASON_NONE,
    JSON_REASON_NAME,
    JSON_REASON_BEGIN_OBJECT,
    JSON_REASON_END_OBJECT,
    JSON_REASON_BEGIN_ARRAY,
    JSON_REASON_END_ARRAY,
    JSON_REASON_VALUE
}
json_reason_t;

typedef struct _json_parser json_parser_t;

typedef json_result_t (*json_parser_callback_t)(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* value,
    void* callback_data);

typedef struct _json_allocator
{
    void* (*ja_malloc)(size_t size);
    void (*ja_free)(void *ptr);
}
json_allocator_t;

typedef struct _json_node
{
    /* Name of the JSON object */
    const char* name;

    /* Integer value if JSON object name is a number (else UINT64_MAX) */
    uint64_t number;

    /* The array size (if an array) */
    size_t size;

    /* The array index (if an array) */
    size_t index;
}
json_node_t;

struct _json_parser
{
    unsigned int magic;
    char* data;
    char* ptr;
    char* end;
    int scan;
    json_parser_callback_t callback;
    void* callback_data;
    json_node_t path[JSON_MAX_NESTING];
    size_t depth;
    json_allocator_t* allocator;
    void (*trace)(
        json_parser_t* parser,
        const char* file,
        unsigned int line,
        const char* func,
        const char* message);
};

json_result_t json_parser_init(
    json_parser_t* self,
    char* data,
    size_t size,
    json_parser_callback_t callback,
    void* callback_data,
    json_allocator_t* allocator);

json_result_t json_parser_parse(json_parser_t* self);

json_result_t json_match(json_parser_t* parser, const char* pattern);

typedef void (*json_write_t)(
    void* stream,
    const void* buf,
    size_t count);

void json_print_value(
    json_write_t write,
    void* stream,
    json_type_t type,
    const json_union_t* un);

json_result_t json_print(
    json_write_t write,
    void* write_data,
    const char* json_data,
    size_t json_size,
    json_allocator_t* allocator);

void json_dump_path(
    json_write_t write,
    void* stream,
    json_parser_t* parser);

#endif /* _JSON_H */
