/*
**==============================================================================
**
** Copyright (c) Microsoft Corporation
**
** All rights reserved.
**
** MIT License
**
** Permission is hereby granted, free of charge, to any person obtaining a copy ** of this software and associated documentation files (the ""Software""), to 
** deal in the Software without restriction, including without limitation the 
** rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
** sell copies of the Software, and to permit persons to whom the Software is 
** furnished to do so, subject to the following conditions: The above copyright ** notice and this permission notice shall be included in all copies or 
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

#include <stdio.h>
#include <stdbool.h>

#define JSON_MAX_NESTING 256

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
    signed long long integer;
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

struct _json_parser
{
    unsigned int magic;
    char* data;
    char* ptr;
    char* end;
    json_parser_callback_t callback;
    void* callback_data;
    const char* path[JSON_MAX_NESTING];
    size_t depth;
};

json_result_t json_parser_init(
    json_parser_t* self,
    char* data,
    size_t size,
    json_parser_callback_t callback,
    void* callback_data);

json_result_t json_parser_parse(json_parser_t* self);

void json_print_value(
    FILE* os,
    json_type_t type,
    const json_union_t* un);

json_result_t json_print(
    FILE* os,
    const char* json_data,
    size_t json_size);

json_result_t json_match(
    json_parser_t* parser,
    const char* pattern,
    unsigned long* index);

void json_dump_path(const char* path[], size_t depth);

#endif /* _JSON_H */
