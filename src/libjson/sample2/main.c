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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <json.h>
#include <sys/stat.h>
#include <string.h>

const char* arg0;

typedef struct _callback_data
{
    int depth;
    int newline;
    int comma;
    char* ptr;
    size_t size;
    FILE* stream;
}
callback_data_t;

static void _print_string(const char* str, callback_data_t* cd)
{
    fprintf(cd->stream, "\"");

    while (*str)
    {
        char c = *str++;

        switch (c)
        {
            case '"':
                fprintf(cd->stream, "\\\"");
                break;
            case '\\':
                fprintf(cd->stream, "\\\\");
                break;
            case '\b':
                fprintf(cd->stream, "\\b");
                break;
            case '\f':
                fprintf(cd->stream, "\\f");
                break;
            case '\n':
                fprintf(cd->stream, "\\n");
                break;
            case '\r':
                fprintf(cd->stream, "\\r");
                break;
            case '\t':
                fprintf(cd->stream, "\\t");
                break;
            default:
            {
                if (isprint(c))
                    fprintf(cd->stream, "%c", c);
                else
                    fprintf(cd->stream, "\\u%04X", c);
            }
        }
    }

    fprintf(cd->stream, "\"");
}

static void _print_value(
    json_type_t type,
    const json_union_t* value,
    callback_data_t* cd)
{
    switch (type)
    {
        case JSON_TYPE_NULL:
            fprintf(cd->stream, "null");
            break;
        case JSON_TYPE_BOOLEAN:
            fprintf(cd->stream, "%s", value->boolean ? "true" : "false");
            break;
        case JSON_TYPE_INTEGER:
            fprintf(cd->stream, "%ld", value->integer);
            break;
        case JSON_TYPE_REAL:
            fprintf(cd->stream, "%E", value->real);
            break;
        case JSON_TYPE_STRING:
            _print_string(value->string, cd);
            break;
        default:
            break;
    }
}

static void _indent(int depth, callback_data_t* cd)
{
    size_t i;

    for (i = 0; i < depth; i++)
        fprintf(cd->stream, "  ");
}

static json_result_t _callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* cd_)
{
    callback_data_t* cd= (callback_data_t*)cd_;

    /* Print commas */
    if (reason != JSON_REASON_END_ARRAY &&
        reason != JSON_REASON_END_OBJECT &&
        cd->comma)
    {
        cd->comma = 0;
        fprintf(cd->stream, ",");
    }

    /* Decrease depth */
    if (reason == JSON_REASON_END_OBJECT ||
        reason == JSON_REASON_END_ARRAY)
    {
        cd->depth--;
    }

    /* Print newline */
    if (cd->newline)
    {
        cd->newline = 0;
        fprintf(cd->stream, "\n");
        _indent(cd->depth, cd);
    }

    switch (reason)
    {
        case JSON_REASON_NONE:
        {
            /* Unreachable */
            break;
        }
        case JSON_REASON_NAME:
        {
            _print_string(un->string, cd);
            fprintf(cd->stream, ": ");
            cd->comma = 0;
            break;
        }
        case JSON_REASON_BEGIN_OBJECT:
        {
            cd->depth++;
            cd->newline = 1;
            cd->comma = 0;
            fprintf(cd->stream, "{");
            break;
        }
        case JSON_REASON_END_OBJECT:
        {
            cd->newline = 1;
            cd->comma = 1;
            fprintf(cd->stream, "}");
            break;
        }
        case JSON_REASON_BEGIN_ARRAY:
        {
            cd->depth++;
            cd->newline = 1;
            cd->comma = 0;
            fprintf(cd->stream, "[");
            break;
        }
        case JSON_REASON_END_ARRAY:
        {
            cd->newline = 1;
            cd->comma = 1;
            fprintf(cd->stream, "]");
            break;
        }
        case JSON_REASON_VALUE:
        {
#if 0
            json_dump_path(parser);
#endif
            cd->newline = 1;
            cd->comma = 1;
            _print_value(type, un, cd);
            break;
        }
    }

    /* Final newline */
    if (reason == JSON_REASON_END_OBJECT ||
        reason == JSON_REASON_END_ARRAY)
    {
        if (cd->depth == 0)
            fprintf(cd->stream, "\n");
    }

    return JSON_OK;
}

static int _load_file(
    const char* path,
    size_t extra_bytes,
    void** data_out,
    size_t* size_out)
{
    int ret = -1;
    FILE* is = NULL;
    void* data = NULL;
    size_t size;

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            goto done;

        size = (size_t)st.st_size;
    }

    /* Allocate memory */
    if (!(data = malloc(size + extra_bytes)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(data, 1, size, is) != size)
        goto done;

    /* Zero-fill any extra bytes */
    if (extra_bytes)
        memset((unsigned char*)data + size, 0, extra_bytes);

    *data_out = data;
    *size_out = size;
    data = NULL;

    ret = 0;

done:

    if (data)
        free(data);

    if (is)
        fclose(is);

    return ret;
}

static void _trace(
    json_parser_t* parser,
    const char* file,
    unsigned int line,
    const char* func,
    const char* message)
{
    (void)parser;
    fprintf(stderr, "TRACE: %s(%u): %s(): %s\n", file, line, func, message);
}

static void _parse(const char* path)
{
    json_parser_t parser;
    char* data;
    size_t size;
    json_result_t r;
    callback_data_t cd;
    static json_allocator_t allocator =
    {
        malloc,
        free,
    };

    cd.depth = 0;
    cd.newline = 0;
    cd.comma = 0;

    if (_load_file(path, 1, (void**)&data, &size) != 0)
    {
        fprintf(stderr, "%s: failed to access '%s'\n", arg0, path);
        exit(1);
    }

    if (!(cd.stream = open_memstream(&cd.ptr, &cd.size)))
    {
        fprintf(stderr, "%s: open_memstream() failed\n", arg0);
        exit(1);
    }

    if ((r = json_parser_init(&parser, data, size, _callback,
        &cd, &allocator)) != JSON_OK)
    {
        fprintf(stderr, "%s: json_parser_init() failed: %d\n", arg0, r);
        exit(1);
    }

    parser.trace = _trace;

    if ((r = json_parser_parse(&parser)) != JSON_OK)
    {
        fprintf(stderr, "%s: json_parser_parse() failed: %d\n", arg0, r);
        exit(1);
    }

    if (cd.depth != 0)
    {
        fprintf(stderr, "%s: unterminated objects\n", arg0);
        exit(1);
    }

    fclose(cd.stream);

    printf("%s", cd.ptr);
}

int main(int argc, char** argv)
{
    arg0 = argv[0];

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s path\n", argv[0]);
        exit(1);
    }

    _parse(argv[1]);

    return 0;
}
