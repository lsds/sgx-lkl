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
*** of this software and associated documentation files (the ""Software""), to
** deal in the Software without restriction, including without limitation the
** rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
** sell copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions: The above copyright
*** notice and this permission notice shall be included in all copies or
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

#include "enclave/oe_compat.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "shared/json.h"

#define JSON_STRLIT(STR) STR, sizeof(STR) - 1

#define RETURN(VALUE) \
    do                \
    {                 \
        return VALUE; \
    } while (0)

#define RAISE(RAISE)                                       \
    do                                                     \
    {                                                      \
        result = RAISE;                                    \
        __raise(__FILE__, __LINE__, __FUNCTION__, result); \
        goto done;                                         \
    } while (0)

static __inline__ void __raise(
    const char* file,
    uint32_t line,
    const char* func,
    json_result_t result)
{
#ifdef TRACE_RAISE
    const char* str = json_result_string(result);
    printf("RAISE: %s(%u): %s(): %s(%u)\n", file, line, func, str, result);
    fflush(stdout);
#else
    (void)file;
    (void)line;
    (void)func;
    (void)result;
#endif
}

static unsigned char _CharToHexNibble(char c)
{
    c = tolower(c);

    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return 0xa + (c - 'a');

    return 0xFF;
}

static int _IsNumberChar(char c)
{
    return isdigit(c) || c == '-' || c == '+' || c == 'e' || c == 'E' ||
           c == '.';
}

static int _IsDecimalOrExponent(char c)
{
    return c == '.' || c == 'e' || c == 'E';
}

static int _HexStr4ToUint(const char* s, unsigned int* x)
{
    unsigned int n0 = _CharToHexNibble(s[0]);
    unsigned int n1 = _CharToHexNibble(s[1]);
    unsigned int n2 = _CharToHexNibble(s[2]);
    unsigned int n3 = _CharToHexNibble(s[3]);

    if ((n0 | n1 | n2 | n3) & 0xF0)
        return -1;

    *x = (n0 << 12) | (n1 << 8) | (n2 << 4) | n3;
    return 0;
}

static json_result_t _invoke_callback(
    json_parser_t* self,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un)
{
    return self->callback(self, reason, type, un, self->callback_data);
}

static json_result_t _GetString(json_parser_t* self, char** str)
{
    char* start = self->ptr;
    char* p = start;
    const char* end = self->end;
    int escaped = 0;

    /* Save the start of the string */
    *str = p;

    /* Find the closing quote */
    while (p != end && *p != '"')
    {
        if (*p++ == '\\')
        {
            escaped = 1;

            if (*p == 'u')
            {
                if (end - p < 4)
                    RETURN(JSON_EOF);
                p += 4;
            }
            else
            {
                if (p == end)
                    RETURN(JSON_EOF);
                p++;
            }
        }
    }

    if (p == end || *p != '"')
        RETURN(JSON_EOF);

    /* Update the os */
    self->ptr += p - start + 1;

    /* Overwrite the '"' character */
    *p = '\0';
    end = p;

    /* ATTN.B: store length (end-p) to str[-1] */

    /* Process escaped characters (if any) */
    if (escaped)
    {
        p = start;

        while (*p)
        {
            /* Handled escaped characters */
            if (*p == '\\')
            {
                p++;

                if (!*p)
                    RETURN(JSON_EOF);

                switch (*p)
                {
                    case '"':
                        p[-1] = '"';
                        memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case '\\':
                        p[-1] = '\\';
                        memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case '/':
                        p[-1] = '/';
                        memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'b':
                        p[-1] = '\b';
                        memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'f':
                        p[-1] = '\f';
                        memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'n':
                        p[-1] = '\n';
                        memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'r':
                        p[-1] = '\r';
                        memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 't':
                        p[-1] = '\t';
                        memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'u':
                    {
                        unsigned int x;

                        p++;

                        /* Expecting 4 hex digits: XXXX */
                        if (end - p < 4)
                            RETURN(JSON_EOF);

                        if (_HexStr4ToUint(p, &x) != 0)
                            RETURN(JSON_BAD_SYNTAX);

                        if (x >= 256)
                        {
                            /* ATTN.B: UTF-8 not supported yet! */
                            RETURN(JSON_UNSUPPORTED);
                        }

                        /* Overwrite '\' character */
                        p[-2] = x;

                        /* Remove "uXXXX" */
                        memmove(p - 1, p + 4, end - p - 3);

                        p = p - 1;
                        end -= 5;
                        break;
                    }
                    default:
                    {
                        RETURN(JSON_FAILED);
                    }
                }
            }
            else
            {
                p++;
            }
        }
    }

    return JSON_OK;
}

static int _Expect(json_parser_t* self, const char* str, size_t len)
{
    if (self->end - self->ptr >= (ptrdiff_t)len &&
        memcmp(self->ptr, str, len) == 0)
    {
        self->ptr += len;
        return 0;
    }

    return -1;
}

static json_result_t _GetValue(json_parser_t* self);

static json_result_t _GetArray(json_parser_t* self)
{
    json_result_t r;
    char c;

    /* array = begin-array [ value *( value-separator value ) ] end-array */
    for (;;)
    {
        /* Skip whitespace */
        while (self->ptr != self->end && isspace(*self->ptr))
            self->ptr++;

        /* Fail if output exhausted */
        if (self->ptr == self->end)
            RETURN(JSON_EOF);

        /* Read the next character */
        c = *self->ptr++;

        if (c == ',')
        {
            continue;
        }
        else if (c == ']')
        {
            break;
        }
        else
        {
            self->ptr--;

            if ((r = _GetValue(self)) != JSON_OK)
            {
                RETURN(r);
            }
        }
    }

    return JSON_OK;
}

static json_result_t _GetObject(json_parser_t* self)
{
    json_result_t r;
    char c;

    if ((r = _invoke_callback(
             self, JSON_REASON_BEGIN_OBJECT, JSON_TYPE_NULL, NULL)) != JSON_OK)
    {
        RETURN(r);
    }

    if (self->depth++ == JSON_MAX_NESTING)
        RETURN(JSON_NESTING_OVERFLOW);

    /* Expect: member = string name-separator value */
    for (;;)
    {
        /* Skip whitespace */
        while (self->ptr != self->end && isspace(*self->ptr))
            self->ptr++;

        /* Fail if output exhausted */
        if (self->ptr == self->end)
            RETURN(JSON_EOF);

        /* Read the next character */
        c = *self->ptr++;

        if (c == '"')
        {
            json_union_t un;

            /* Get name */
            if ((r = _GetString(self, (char**)&un.string)) != JSON_OK)
                RETURN(r);

            self->path[self->depth - 1] = un.string;

            if ((r = _invoke_callback(
                     self, JSON_REASON_NAME, JSON_TYPE_STRING, &un)) != JSON_OK)
            {
                RETURN(r);
            }

            /* Expect: name-separator(':') */
            {
                /* Skip whitespace */
                while (self->ptr != self->end && isspace(*self->ptr))
                    self->ptr++;

                /* Fail if output exhausted */
                if (self->ptr == self->end)
                    RETURN(JSON_EOF);

                /* Read the next character */
                c = *self->ptr++;

                if (c != ':')
                    RETURN(JSON_BAD_SYNTAX);
            }

            /* Expect: value */
            if ((r = _GetValue(self)) != JSON_OK)
                RETURN(r);
        }
        else if (c == '}')
        {
            break;
        }
    }

    if (self->depth == 0)
        RETURN(JSON_NESTING_UNDERFLOW);

    if ((r = _invoke_callback(
             self, JSON_REASON_END_OBJECT, JSON_TYPE_NULL, NULL)) != JSON_OK)
    {
        RETURN(r);
    }

    self->depth--;

    return JSON_OK;
}

static json_result_t _GetNumber(
    json_parser_t* self,
    json_type_t* type,
    json_union_t* un)
{
    char c;
    int isInteger = 1;
    char* end;
    const char* start = self->ptr;

    /* Skip over any characters that can comprise a number */
    while (self->ptr != self->end && _IsNumberChar(*self->ptr))
    {
        c = *self->ptr;
        self->ptr++;

        if (_IsDecimalOrExponent(c))
            isInteger = 0;
    }

    if (isInteger)
    {
        *type = JSON_TYPE_INTEGER;
        un->integer = strtoll(start, &end, 10);
    }
    else
    {
        *type = JSON_TYPE_REAL;
        un->real = strtod(start, &end);
    }

    if (!end || end != self->ptr)
        RETURN(JSON_BAD_SYNTAX);

    return JSON_OK;
}

/* value = false / null / true / object / array / number / string */
static json_result_t _GetValue(json_parser_t* self)
{
    char c;
    json_result_t r;

    /* Skip whitespace */
    while (self->ptr != self->end && isspace(*self->ptr))
        self->ptr++;

    /* Fail if output exhausted */
    if (self->ptr == self->end)
        RETURN(JSON_EOF);

    /* Read the next character */
    c = tolower(*self->ptr++);

    switch (c)
    {
        case 'f':
        {
            json_union_t un;

            if (_Expect(self, JSON_STRLIT("alse")) != 0)
                RETURN(JSON_BAD_SYNTAX);

            un.boolean = 0;

            if ((r = _invoke_callback(
                     self, JSON_REASON_VALUE, JSON_TYPE_BOOLEAN, &un)) !=
                JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case 'n':
        {
            if (_Expect(self, JSON_STRLIT("ull")) != 0)
                RETURN(JSON_BAD_SYNTAX);

            if ((r = _invoke_callback(
                     self, JSON_REASON_VALUE, JSON_TYPE_NULL, NULL)) != JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case 't':
        {
            json_union_t un;

            if (_Expect(self, JSON_STRLIT("rue")) != 0)
                RETURN(JSON_BAD_SYNTAX);

            un.boolean = 1;

            if ((r = _invoke_callback(
                     self, JSON_REASON_VALUE, JSON_TYPE_BOOLEAN, &un)) !=
                JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case '{':
        {
            if ((r = _GetObject(self)) != JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case '[':
        {
            if ((r = _invoke_callback(
                     self, JSON_REASON_BEGIN_ARRAY, JSON_TYPE_NULL, NULL)) !=
                JSON_OK)
            {
                RETURN(r);
            }

            if ((r = _GetArray(self)) != JSON_OK)
                RETURN(JSON_BAD_SYNTAX);

            if ((r = _invoke_callback(
                     self, JSON_REASON_END_ARRAY, JSON_TYPE_NULL, NULL)) !=
                JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case '"':
        {
            json_union_t un;

            if ((r = _GetString(self, (char**)&un.string)) != JSON_OK)
                RETURN(JSON_BAD_SYNTAX);

            if ((r = _invoke_callback(
                     self, JSON_REASON_VALUE, JSON_TYPE_STRING, &un)) !=
                JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        default:
        {
            json_type_t type;
            json_union_t un;

            self->ptr--;

            if ((r = _GetNumber(self, &type, &un)) != JSON_OK)
                RETURN(JSON_BAD_SYNTAX);

            if ((r = _invoke_callback(self, JSON_REASON_VALUE, type, &un)) !=
                JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
    }

    return JSON_OK;
}

json_result_t json_parser_init(
    json_parser_t* self,
    char* data,
    size_t size,
    json_parser_callback_t callback,
    void* callback_data)
{
    if (!self || !data || !size || !callback)
        return JSON_BAD_PARAMETER;

    memset(self, 0, sizeof(json_parser_t));
    self->data = data;
    self->ptr = data;
    self->end = data + size;
    self->callback = callback;
    self->callback_data = callback_data;

    return JSON_OK;
}

json_result_t json_parser_parse(json_parser_t* self)
{
    char c;

    /* Check parameters */
    if (!self)
        return JSON_BAD_PARAMETER;

    /* Expect '{' */
    {
        /* Skip whitespace */
        while (self->ptr != self->end && isspace(*self->ptr))
            self->ptr++;

        /* Fail if output exhausted */
        if (self->ptr == self->end)
            RETURN(JSON_EOF);

        /* Read the next character */
        c = *self->ptr++;

        /* Expect object-begin */
        if (c != '{')
            return JSON_BAD_SYNTAX;
    }

    return _GetObject(self);
}

static int _strtou64(uint64_t* x, const char* str)
{
    char* end;

    *x = strtoull(str, &end, 10);

    if (!end || *end != '\0')
        return -1;

    return 0;
}

json_result_t json_match(
    json_parser_t* parser,
    const char* pattern,
    unsigned long* index)
{
    json_result_t result = JSON_UNEXPECTED;
    char buf[256];
    char* ptr = NULL;
    const char* pattern_path[JSON_MAX_NESTING];
    size_t pattern_depth = 0;
    unsigned long n = 0;
    size_t pattern_len;

    if (!parser || !parser->path || !pattern)
        RAISE(JSON_BAD_PARAMETER);

    /* Make a copy of the pattern that can be modified */
    {
        pattern_len = strlen(pattern);

        if (pattern_len < sizeof(buf))
            ptr = buf;
        else if (!(ptr = malloc(pattern_len + 1)))
            RAISE(JSON_OUT_OF_MEMORY);

        strcpy(ptr, pattern);
    }

    /* Split the pattern into tokens */
    {
        char* p;
        char* save;

        for (p = strtok_r(ptr, ".", &save); p; p = strtok_r(NULL, ".", &save))
        {
            if (pattern_depth == JSON_MAX_NESTING)
                RAISE(JSON_NESTING_OVERFLOW);

            pattern_path[pattern_depth++] = p;
        }
    }

    /* Return false if the path sizes are different */
    if (parser->depth != pattern_depth)
    {
        result = JSON_NO_MATCH;
        goto done;
    }

    /* Compare the elements */
    for (size_t i = 0; i < pattern_depth; i++)
    {
        if (strcmp(pattern_path[i], "#") == 0)
        {
            if (_strtou64(&n, parser->path[i]) != 0)
                RAISE(JSON_TYPE_MISMATCH);
        }
        else if (strcmp(pattern_path[i], parser->path[i]) != 0)
        {
            result = JSON_NO_MATCH;
            goto done;
        }
    }

    if (index)
        *index = n;

    result = JSON_OK;

done:

    if (ptr && ptr != buf)
        free(ptr);

    return result;
}

const char* json_result_string(json_result_t result)
{
    switch (result)
    {
        case JSON_OK:
            return "JSON_OK";
        case JSON_FAILED:
            return "JSON_FAILED";
        case JSON_UNEXPECTED:
            return "JSON_UNEXPECTED";
        case JSON_BAD_PARAMETER:
            return "JSON_BAD_PARAMETER";
        case JSON_OUT_OF_MEMORY:
            return "JSON_OUT_OF_MEMORY";
        case JSON_EOF:
            return "JSON_EOF";
        case JSON_UNSUPPORTED:
            return "JSON_UNSUPPORTED";
        case JSON_BAD_SYNTAX:
            return "JSON_BAD_SYNTAX";
        case JSON_TYPE_MISMATCH:
            return "JSON_TYPE_MISMATCH";
        case JSON_NESTING_OVERFLOW:
            return "JSON_NESTING_OVERFLOW";
        case JSON_NESTING_UNDERFLOW:
            return "JSON_NESTING_UNDERFLOW";
        case JSON_BUFFER_OVERFLOW:
            return "JSON_BUFFER_OVERFLOW";
        case JSON_UNKNOWN_VALUE:
            return "JSON_UNKNOWN_VALUE";
        case JSON_OUT_OF_BOUNDS:
            return "JSON_OUT_OF_BOUNDS";
        case JSON_NO_MATCH:
            return "JSON_NO_MATCH";
    }

    /* Unreachable */
    return "UNKNOWN";
}