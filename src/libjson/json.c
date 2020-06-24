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

#include "json.h"
#include <stdio.h>

/*
**==============================================================================
**
** libc compatibility:
**
**==============================================================================
*/

#ifndef NULL
#define NULL ((void*)0)
#endif

#define UINT64_MAX 0xffffffffffffffffu
#define LONG_MAX 0x7fffffffffffffffL
#define ULONG_MAX (2UL * LONG_MAX + 1)
#define INT64_MIN (-1 - 0x7fffffffffffffff)

typedef unsigned int uint32_t;
typedef unsigned long size_t;
typedef long ptrdiff_t;

static int _tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? (c - ' ') : c;
}

static int _isdigit(int c)
{
    return (c >= '0' && c <= '9');
}

static int _isspace(int c)
{
    return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' ||
           c == '\v';
}

static int _islower(int c)
{
    return (c >= 'a' && c <= 'z');
}

static int _isupper(int c)
{
    return (c >= 'A' && c <= 'Z');
}

static int _isprint(int c)
{
    if (_isdigit(c) || _islower(c) || _isupper(c))
        return 1;

    switch (c)
    {
        case ' ':
        case '!':
        case '"':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case ',':
        case '-':
        case '.':
        case '/':
        case ':':
        case ';':
        case '<':
        case '=':
        case '>':
        case '?':
        case '@':
        case '[':
        case '\\':
        case ']':
        case '^':
        case '_':
        case '`':
        case '{':
        case '|':
        case '}':
        case '~':
            return 1;
        default:
            break;
    }

    return 0;
}

static void* _memset(void* s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

    while (n--)
        *p++ = c;

    return s;
}

static void* _memcpy(void* dest, const void* src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    unsigned char* q = (unsigned char*)src;

    while (n--)
        *p++ = *q++;

    return dest;
}

static int _memcmp(const void* s1, const void* s2, size_t n)
{
    unsigned char* p = (unsigned char*)s1;
    unsigned char* q = (unsigned char*)s2;

    while (n--)
    {
        if (*p < *q)
            return -1;
        else if (*p > *q)
            return 1;

        p++;
        q++;
    }

    return 0;
}

static void* _memmove(void* dest_, const void* src_, size_t n)
{
    char* dest = (char*)dest_;
    const char* src = (const char*)src_;

    if (dest != src && n > 0)
    {
        if (dest <= src)
        {
            _memcpy(dest, src, n);
        }
        else
        {
            for (src += n, dest += n; n--; dest--, src--)
                dest[-1] = src[-1];
        }
    }

    return dest;
}

static size_t _strlen(const char* s)
{
    size_t n = 0;

    while (*s++)
        n++;

    return n;
}

static int _strcmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

static size_t _strlcpy(char* dest, const char* src, size_t size)
{
    const char* start = src;

    if (size)
    {
        char* end = dest + size - 1;

        while (*src && dest != end)
            *dest++ = (char)*src++;

        *dest = '\0';
    }

    while (*src)
        src++;

    return (size_t)(src - start);
}

static size_t _strlcat(char* dest, const char* src, size_t size)
{
    size_t n = 0;

    if (size)
    {
        char* end = dest + size - 1;

        while (*dest && dest != end)
        {
            dest++;
            n++;
        }

        while (*src && dest != end)
        {
            n++;
            *dest++ = *src++;
        }

        *dest = '\0';
    }

    while (*src)
    {
        src++;
        n++;
    }

    return n;
}

//
// If c is a digit character:
//     then: _digit[c] yields the integer value for that digit character.
//     else: _digit[c] yields 0xFF.
//
// Digit characters fall within these ranges: ['0'-'9'] and ['A'-'Z'].
//
// Examples:
//     _digit['9'] => 9
//     _digit['A'] => 10
//     _digit['Z'] => 35
//     _digit['?'] => 0xFF
//
static const unsigned char _digit[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
};

/* Return true if c is a digit character with the given base */
static int _isdigit2(char c, int base)
{
    return _digit[(unsigned char)c] < base;
}

long int _strtol(const char* nptr, char** endptr, int base)
{
    const char* p;
    unsigned long x = 0;
    int negative = 0;

    if (endptr)
        *endptr = (char*)nptr;

    if (!nptr || base < 0)
        return 0;

    /* Set scanning pointer to nptr */
    p = nptr;

    /* Skip any leading whitespace */
    while (_isspace(*p))
        p++;

    /* Handle '+' and '-' */
    if (p[0] == '+')
    {
        p++;
    }
    else if (p[0] == '-')
    {
        negative = 1;
        p++;
    }

    /* If base is zero, deduce the base from the prefix. */
    if (base == 0)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            base = 16;
        }
        else if (p[0] == '0')
        {
            base = 8;
        }
        else
        {
            base = 10;
        }
    }

    /* Remove any base 16 prefix. */
    if (base == 16)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
        }
    }

    /* Remove any base 8 prefix. */
    if (base == 8)
    {
        if (p[0] == '0')
        {
            p++;
        }
    }

    for (; *p && _isdigit2(*p, base); p++)
    {
        /* Multiply by base */
        {
            /* Check for overflow */
            if (x > UINT64_MAX / (unsigned long)base)
            {
                if (endptr)
                    *endptr = (char*)p;

                return UINT64_MAX;
            }

            x = x * (unsigned long)base;
        }

        /* Add digit */
        {
            const unsigned long digit = _digit[(unsigned char)*p];

            /* Check for overflow */
            if (digit > ULONG_MAX - x)
            {
                if (endptr)
                    *endptr = (char*)p;

                return UINT64_MAX;
            }

            x += digit;
        }
    }

    /* Return zero if no digits were found */
    if (p == nptr)
        return 0;

    if (endptr)
        *endptr = (char*)p;

    /* Invert if negative */
    if (negative)
    {
        if (x > LONG_MAX)
        {
            if (x == (unsigned long)LONG_MAX + 1)
                return x;
            else
                return 0;
        }
        x = (unsigned long)-(long)x;
    }

    return (long)x;
}

unsigned long int _strtoul(const char* nptr, char** endptr, int base)
{
    return (unsigned long)_strtol(nptr, endptr, base);
}

double _strtod(const char* nptr, char** endptr)
{
    const char* p;
    int negative = 0;
    int exp_negative = 0;
    unsigned long x;
    unsigned long y = 0;
    unsigned long r = 1;
    unsigned long exp = 0;
    int have_x = 0;
    double z;

    if (endptr)
        *endptr = (char*)nptr;

    if (!nptr)
        return 0.0;

    /* Set scanning pointer to nptr */
    p = nptr;

    /* Skip any leading whitespace */
    while (_isspace(*p))
        p++;

    /* Handle '+' and '-' */
    if (p[0] == '+')
    {
        p++;
    }
    else if (p[0] == '-')
    {
        negative = 1;
        p++;
    }

    /* Parse the leading number */
    {
        char* end;
        x = _strtoul(p, &end, 10);

        if (p != end)
        {
            have_x = 1;
            *endptr = (char*)end;
        }

        p = end;
    }

    /* Parse the decimal and trailing number */
    if (*p == '.')
    {
        char* end;

        p++;
        y = _strtoul(p, &end, 10);

        if (p != end)
        {
            size_t n;
            *endptr = (char*)end;

            /* Calculate the number of decimal places */
            n = end - p;
            p = end;

            /* Find a divisor */
            while (n--)
                r *= 10;
        }
        else if (have_x)
        {
            *endptr = (char*)p;
        }
        else
        {
            *endptr = (char*)(p - 1);
            return 0.0;
        }
    }

    /* Handle exponent if any */
    if (*p == 'e' || *p == 'E')
    {
        char* end;
        p++;

        if (*p == '-')
            exp_negative = 1;

        if (*p == '-' || *p == '+')
            p++;

        exp = _strtoul(p, &end, 10);

        if (p != end)
            *endptr = (char*)end;

        p = end;
    }

    z = (double)x + ((double)y / (double)r);

    if (exp)
    {
        for (size_t i = 0; i < exp; i++)
        {
            if (exp_negative)
                z /= 10;
            else
                z *= 10;
        }
    }

    return negative ? -z : z;
}

/*
**==============================================================================
**
** JSON parser implementation:
**
**==============================================================================
*/

#define STRLIT(STR) STR, sizeof(STR) - 1

#define RAISE(RESULT)                                                 \
    do                                                                \
    {                                                                 \
        json_result_t _r_ = RESULT;                                   \
        result = _r_;                                                 \
        _trace_result(parser, __FILE__, __LINE__, __FUNCTION__, _r_); \
        goto done;                                                    \
    } while (0)

#define CHECK(RESULT)                                                     \
    do                                                                    \
    {                                                                     \
        json_result_t _r_ = RESULT;                                       \
        if (_r_ != JSON_OK)                                               \
        {                                                                 \
            result = _r_;                                                 \
            _trace_result(parser, __FILE__, __LINE__, __FUNCTION__, _r_); \
            goto done;                                                    \
        }                                                                 \
    } while (0)

static void _trace(
    json_parser_t* parser,
    const char* file,
    uint32_t line,
    const char* func,
    const char* message)
{
    if (parser && parser->trace)
        (*parser->trace)(parser, file, line, func, message);
}

static void _trace_result(
    json_parser_t* parser,
    const char* file,
    uint32_t line,
    const char* func,
    json_result_t result)
{
    if (parser && parser->trace)
    {
        char message[64];
        _strlcpy(message, "result: ", sizeof(message));
        _strlcat(message, json_result_string(result), sizeof(message));
        _trace(parser, file, line, func, message);
    }
}

static void* _malloc(json_parser_t* parser, size_t size)
{
    if (!parser || !parser->allocator || !parser->allocator->ja_malloc)
        return NULL;

    return (*parser->allocator->ja_malloc)(size);
}

static void _free(json_parser_t* parser, void* ptr)
{
    if (!parser || !parser->allocator || !parser->allocator->ja_free || !ptr)
        return;

    return (*parser->allocator->ja_free)(ptr);
}

static size_t _split(
    char* s,
    const char sep,
    const char* tokens[],
    size_t num_tokens)
{
    size_t n = 0;

    for (;;)
    {
        if (n == num_tokens)
            return (size_t)-1;

        tokens[n++] = s;

        /* Skip non-separator characters */
        while (*s && *s != sep)
            s++;

        if (!*s)
            break;

        *s++ = '\0';
    }

    return n;
}

static unsigned char _char_to_nibble(char c)
{
    c = _tolower(c);

    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return 0xa + (c - 'a');

    return 0xFF;
}

static int _is_number_char(char c)
{
    return _isdigit(c) || c == '-' || c == '+' || c == 'e' || c == 'E' ||
           c == '.';
}

static int _is_decimal_or_exponent(char c)
{
    return c == '.' || c == 'e' || c == 'E';
}

static int _hex_str4_to_u32(const char* s, uint32_t* x)
{
    uint32_t n0 = _char_to_nibble(s[0]);
    uint32_t n1 = _char_to_nibble(s[1]);
    uint32_t n2 = _char_to_nibble(s[2]);
    uint32_t n3 = _char_to_nibble(s[3]);

    if ((n0 | n1 | n2 | n3) & 0xF0)
        return -1;

    *x = (n0 << 12) | (n1 << 8) | (n2 << 4) | n3;
    return 0;
}

static json_result_t _invoke_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un)
{
    if (parser->scan)
        return JSON_OK;

    return parser->callback(parser, reason, type, un, parser->callback_data);
}

static json_result_t _get_string(json_parser_t* parser, char** str)
{
    json_result_t result = JSON_OK;
    char* start = parser->ptr;
    char* p = start;
    const char* end = parser->end;
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
                    RAISE(JSON_EOF);
                p += 4;
            }
            else
            {
                if (p == end)
                    RAISE(JSON_EOF);
                p++;
            }
        }
    }

    if (p == end || *p != '"')
        RAISE(JSON_EOF);

    /* Update the os */
    parser->ptr += p - start + 1;

    /* Skip modification of text if only scanning */
    if (parser->scan)
    {
        result = JSON_OK;
        goto done;
    }

    /* Overwrite the '"' character */
    *p = '\0';
    end = p;

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
                    RAISE(JSON_EOF);

                switch (*p)
                {
                    case '"':
                        p[-1] = '"';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case '\\':
                        p[-1] = '\\';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case '/':
                        p[-1] = '/';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'b':
                        p[-1] = '\b';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'f':
                        p[-1] = '\f';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'n':
                        p[-1] = '\n';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'r':
                        p[-1] = '\r';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 't':
                        p[-1] = '\t';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'u':
                    {
                        uint32_t x;

                        p++;

                        /* Expecting 4 hex digits: XXXX */
                        if (end - p < 4)
                            RAISE(JSON_EOF);

                        if (_hex_str4_to_u32(p, &x) != 0)
                            RAISE(JSON_BAD_SYNTAX);

                        if (x >= 256)
                        {
                            /* ATTN.B: UTF-8 not supported yet! */
                            RAISE(JSON_UNSUPPORTED);
                        }

                        /* Overwrite '\' character */
                        p[-2] = x;

                        /* Remove "uXXXX" */
                        _memmove(p - 1, p + 4, end - p - 3);

                        p = p - 1;
                        end -= 5;
                        break;
                    }
                    default:
                    {
                        RAISE(JSON_FAILED);
                    }
                }
            }
            else
            {
                p++;
            }
        }
    }

#if 0
    Dump(stdout, "GETSTRING", *str, strlen(*str));
#endif

done:
    return result;
}

static int _expect(json_parser_t* parser, const char* str, size_t len)
{
    if (parser->end - parser->ptr >= (ptrdiff_t)len &&
        _memcmp(parser->ptr, str, len) == 0)
    {
        parser->ptr += len;
        return 0;
    }

    return -1;
}

static json_result_t _get_value(json_parser_t* parser);

static json_result_t _get_array(json_parser_t* parser, size_t* array_size)
{
    json_result_t result = JSON_OK;
    char c;
    size_t index = 0;

    /* array = begin-array [ value *( value-separator value ) ] end-array */
    for (;;)
    {
        /* Skip whitespace */
        while (parser->ptr != parser->end && _isspace(*parser->ptr))
            parser->ptr++;

        /* Fail if output exhausted */
        if (parser->ptr == parser->end)
            RAISE(JSON_EOF);

        /* Read the next character */
        c = *parser->ptr++;

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
            parser->path[parser->depth - 1].index = index++;

            parser->ptr--;
            CHECK(_get_value(parser));

            if (array_size)
                (*array_size)++;
        }
    }

done:
    return result;
}

static int _strtou64(uint64_t* x, const char* str)
{
    char* end;

    *x = _strtoul(str, &end, 10);

    if (!end || *end != '\0')
        return -1;

    return 0;
}

static json_result_t _get_object(json_parser_t* parser)
{
    json_result_t result = JSON_OK;
    char c;

    CHECK(_invoke_callback(
        parser, JSON_REASON_BEGIN_OBJECT, JSON_TYPE_NULL, NULL));

    if (parser->depth++ == JSON_MAX_NESTING)
        RAISE(JSON_NESTING_OVERFLOW);

    /* Expect: member = string name-separator value */
    for (;;)
    {
        /* Skip whitespace */
        while (parser->ptr != parser->end && _isspace(*parser->ptr))
            parser->ptr++;

        /* Fail if output exhausted */
        if (parser->ptr == parser->end)
            RAISE(JSON_EOF);

        /* Read the next character */
        c = *parser->ptr++;

        if (c == '"')
        {
            json_union_t un;

            /* Get name */
            CHECK(_get_string(parser, (char**)&un.string));

            /* Insert node */
            {
                uint64_t n;
                json_node_t node = {un.string, 0, 0, 0};

                if (_strtou64(&n, un.string) == 0)
                    node.number = n;
                else
                    node.number = UINT64_MAX;

                parser->path[parser->depth - 1] = node;
            }

            CHECK(_invoke_callback(
                parser, JSON_REASON_NAME, JSON_TYPE_STRING, &un));

            /* Expect: name-separator(':') */
            {
                /* Skip whitespace */
                while (parser->ptr != parser->end && _isspace(*parser->ptr))
                    parser->ptr++;

                /* Fail if output exhausted */
                if (parser->ptr == parser->end)
                    RAISE(JSON_EOF);

                /* Read the next character */
                c = *parser->ptr++;

                if (c != ':')
                    RAISE(JSON_BAD_SYNTAX);
            }

            /* Expect: value */
            CHECK(_get_value(parser));
        }
        else if (c == '}')
        {
            break;
        }
    }

    if (parser->depth == 0)
        RAISE(JSON_NESTING_UNDERFLOW);

    CHECK(
        _invoke_callback(parser, JSON_REASON_END_OBJECT, JSON_TYPE_NULL, NULL));

    parser->depth--;

done:
    return result;
}

static json_result_t _get_number(
    json_parser_t* parser,
    json_type_t* type,
    json_union_t* un)
{
    json_result_t result = JSON_OK;
    char c;
    int isInteger = 1;
    char* end;
    const char* start = parser->ptr;

    /* Skip over any characters that can comprise a number */
    while (parser->ptr != parser->end && _is_number_char(*parser->ptr))
    {
        c = *parser->ptr;
        parser->ptr++;

        if (_is_decimal_or_exponent(c))
            isInteger = 0;
    }

    if (isInteger)
    {
        *type = JSON_TYPE_INTEGER;
        un->integer = _strtol(start, &end, 10);
    }
    else
    {
        *type = JSON_TYPE_REAL;
        un->real = _strtod(start, &end);
    }

    if (!end || end != parser->ptr)
        RAISE(JSON_BAD_SYNTAX);

done:
    return result;
}

/* value = false / null / true / object / array / number / string */
static json_result_t _get_value(json_parser_t* parser)
{
    json_result_t result = JSON_OK;
    char c;
    json_parser_t* scanner = NULL;

    /* Skip whitespace */
    while (parser->ptr != parser->end && _isspace(*parser->ptr))
        parser->ptr++;

    /* Fail if output exhausted */
    if (parser->ptr == parser->end)
        RAISE(JSON_EOF);

    /* Read the next character */
    c = _tolower(*parser->ptr++);

    switch (c)
    {
        case 'f':
        {
            json_union_t un;

            if (_expect(parser, STRLIT("alse")) != 0)
                RAISE(JSON_BAD_SYNTAX);

            un.boolean = 0;

            CHECK(_invoke_callback(
                parser, JSON_REASON_VALUE, JSON_TYPE_BOOLEAN, &un));

            break;
        }
        case 'n':
        {
            if (_expect(parser, STRLIT("ull")) != 0)
                RAISE(JSON_BAD_SYNTAX);

            CHECK(_invoke_callback(
                parser, JSON_REASON_VALUE, JSON_TYPE_NULL, NULL));

            break;
        }
        case 't':
        {
            json_union_t un;

            if (_expect(parser, STRLIT("rue")) != 0)
                RAISE(JSON_BAD_SYNTAX);

            un.boolean = 1;

            CHECK(_invoke_callback(
                parser, JSON_REASON_VALUE, JSON_TYPE_BOOLEAN, &un));

            break;
        }
        case '{':
        {
            CHECK(_get_object(parser));
            break;
        }
        case '[':
        {
            json_union_t un;

            /* Scan ahead to determine the size of the array */
            {
                size_t array_size = 0;

                if (!(scanner = _malloc(parser, sizeof(json_parser_t))))
                    RAISE(JSON_OUT_OF_MEMORY);

                _memcpy(scanner, parser, sizeof(json_parser_t));
                scanner->scan = 1;

                if (_get_array(scanner, &array_size) != JSON_OK)
                    RAISE(JSON_BAD_SYNTAX);

                _free(parser, scanner);
                scanner = NULL;

                un.integer = (signed long long)array_size;

                parser->path[parser->depth - 1].size = array_size;
            }

            CHECK(_invoke_callback(
                parser, JSON_REASON_BEGIN_ARRAY, JSON_TYPE_INTEGER, &un));

            if (_get_array(parser, NULL) != JSON_OK)
                RAISE(JSON_BAD_SYNTAX);

            CHECK(_invoke_callback(
                parser, JSON_REASON_END_ARRAY, JSON_TYPE_INTEGER, &un));

            break;
        }
        case '"':
        {
            json_union_t un;

            if (_get_string(parser, (char**)&un.string) != JSON_OK)
                RAISE(JSON_BAD_SYNTAX);

            CHECK(_invoke_callback(
                parser, JSON_REASON_VALUE, JSON_TYPE_STRING, &un));
            break;
        }
        default:
        {
            json_type_t type;
            json_union_t un;

            parser->ptr--;

            if (_get_number(parser, &type, &un) != JSON_OK)
                RAISE(JSON_BAD_SYNTAX);

            CHECK(_invoke_callback(parser, JSON_REASON_VALUE, type, &un));
            break;
        }
    }

done:

    if (scanner)
        _free(parser, scanner);

    return result;
}

json_result_t json_parser_init(
    json_parser_t* parser,
    char* data,
    size_t size,
    json_parser_callback_t callback,
    void* callback_data,
    json_allocator_t* allocator)
{
    if (!parser || !data || !size || !callback)
        return JSON_BAD_PARAMETER;

    if (!allocator || !allocator->ja_malloc || !allocator->ja_free)
        return JSON_BAD_PARAMETER;

    _memset(parser, 0, sizeof(json_parser_t));
    parser->data = data;
    parser->ptr = data;
    parser->end = data + size;
    parser->callback = callback;
    parser->callback_data = callback_data;
    parser->allocator = allocator;

    return JSON_OK;
}

json_result_t json_parser_parse(json_parser_t* parser)
{
    json_result_t result = JSON_OK;
    char c;

    /* Check parameters */
    if (!parser)
        return JSON_BAD_PARAMETER;

    /* Expect '{' */
    {
        /* Skip whitespace */
        while (parser->ptr != parser->end && _isspace(*parser->ptr))
            parser->ptr++;

        /* Fail if output exhausted */
        if (parser->ptr == parser->end)
            RAISE(JSON_EOF);

        /* Read the next character */
        c = *parser->ptr++;

        /* Expect object-begin */
        if (c != '{')
            return JSON_BAD_SYNTAX;
    }

    CHECK(_get_object(parser));

done:
    return result;
}

json_result_t json_match(json_parser_t* parser, const char* pattern)
{
    json_result_t result = JSON_UNEXPECTED;
    char buf[256];
    char* ptr = NULL;
    const char* pattern_path[JSON_MAX_NESTING];
    size_t pattern_depth = 0;
    unsigned long n = 0;
    size_t pattern_len;

    if (!parser || !pattern)
        RAISE(JSON_BAD_PARAMETER);

    /* Make a copy of the pattern that can be modified */
    {
        pattern_len = _strlen(pattern);

        if (pattern_len < sizeof(buf))
            ptr = buf;
        else if (!(ptr = _malloc(parser, pattern_len + 1)))
            RAISE(JSON_OUT_OF_MEMORY);

        _strlcpy(ptr, pattern, pattern_len + 1);
    }

    /* Split the pattern into tokens */
    if ((pattern_depth = _split(ptr, '.', pattern_path, JSON_MAX_NESTING)) ==
        (size_t)-1)
    {
        RAISE(JSON_NESTING_OVERFLOW);
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
        if (_strcmp(pattern_path[i], "#") == 0)
        {
            if (_strtou64(&n, parser->path[i].name) != 0)
                RAISE(JSON_TYPE_MISMATCH);
        }
        else if (_strcmp(pattern_path[i], parser->path[i].name) != 0)
        {
            result = JSON_NO_MATCH;
            goto done;
        }
    }

    result = JSON_OK;

done:

    if (ptr && ptr != buf)
        _free(parser, ptr);

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

static void _Indent(json_write_t write, void* stream, size_t depth)
{
    size_t i;

    for (i = 0; i < depth; i++)
        (*write)(stream, STRLIT("  "));
}

static void _byte_to_hex_string(unsigned char c, char hex[3])
{
    const unsigned char hi = (c & 0xf0) >> 4;
    ;
    const unsigned char lo = c & 0x0f;

    hex[0] = (hi >= 0xa) ? (hi - 0xa + 'A') : (hi + '0');
    hex[1] = (lo >= 0xa) ? (lo - 0xa + 'A') : (lo + '0');
    hex[2] = '\0';
}

typedef struct _strbuf
{
    char data[256];
} strbuf_t;

static const char* _i64tostr(strbuf_t* buf, int64_t x, size_t* size)
{
    char* p;
    int neg = 0;
    static const char _str[] = "-9223372036854775808";
    char* end = buf->data + sizeof(buf->data) - 1;

    if (x == INT64_MIN)
    {
        *size = sizeof(_str) - 1;
        return _str;
    }

    if (x < 0)
    {
        neg = 1;
        x = -x;
    }

    p = end;
    *p = '\0';

    do
    {
        *--p = (char)('0' + x % 10);
    } while (x /= 10);

    if (neg)
        *--p = '-';

    if (size)
        *size = (size_t)(end - p);

    return p;
}

static const char* _dtostr(strbuf_t* buf, double x, size_t* size)
{
    strbuf_t whole_buf;
    strbuf_t frac_buf;
    const char* whole_str;
    const char* frac_str;

    long whole = (long)x;
    double frac = x - whole;

    /* ATTN: precision limited to 10 decimal places */
    for (size_t i = 0; i < 10; i++)
        frac *= 10;

    whole_str = _i64tostr(&whole_buf, whole, NULL);
    frac_str = _i64tostr(&frac_buf, frac, NULL);
    size_t frac_len = _strlen(frac_str);

    /* Remove trailing zeros from the fractional part */
    for (char* p = (char*)frac_str + frac_len; p != frac_str; p--)
    {
        if (p[-1] == '0')
            p[-1] = '\0';
    }

    _strlcpy(buf->data, whole_str, sizeof(buf->data));
    _strlcat(buf->data, ".", sizeof(buf->data));

    if (*frac_str == '\0')
        _strlcat(buf->data, "0", sizeof(buf->data));
    else
        _strlcat(buf->data, frac_str, sizeof(buf->data));

    *size = _strlen(buf->data);

    return buf->data;
}

static void _PrintString(json_write_t write, void* stream, const char* str)
{
    (*write)(stream, STRLIT("\""));

    while (*str)
    {
        char c = *str++;

        switch (c)
        {
            case '"':
                (*write)(stream, STRLIT("\\\""));
                break;
            case '\\':
                (*write)(stream, STRLIT("\\\\"));
                break;
            case '/':
                (*write)(stream, STRLIT("\\/"));
                break;
            case '\b':
                (*write)(stream, STRLIT("\\b"));
                break;
            case '\f':
                (*write)(stream, STRLIT("\\f"));
                break;
            case '\n':
                (*write)(stream, STRLIT("\\n"));
                break;
            case '\r':
                (*write)(stream, STRLIT("\\r"));
                break;
            case '\t':
                (*write)(stream, STRLIT("\\t"));
                break;
            default:
            {
                if (_isprint(c))
                {
                    (*write)(stream, &c, 1);
                }
                else
                {
                    char hex[3];
                    _byte_to_hex_string(c, hex);
                    (*write)(stream, STRLIT("\\u00"));
                    (*write)(stream, hex, 2);
                }
            }
        }
    }

    (*write)(stream, STRLIT("\""));
}

void json_print_value(
    json_write_t write,
    void* stream,
    json_type_t type,
    const json_union_t* un)
{
    switch (type)
    {
        case JSON_TYPE_NULL:
        {
            (*write)(stream, STRLIT("null"));
            break;
        }
        case JSON_TYPE_BOOLEAN:
        {
            if (un->boolean)
                (*write)(stream, STRLIT("true"));
            else
                (*write)(stream, STRLIT("false"));
            break;
        }
        case JSON_TYPE_INTEGER:
        {
            strbuf_t buf;
            size_t size;
            const char* str = _i64tostr(&buf, un->integer, &size);
            (*write)(stream, str, size);
            break;
        }
        case JSON_TYPE_REAL:
        {
            strbuf_t buf;
            size_t size;
            const char* str = _dtostr(&buf, un->real, &size);
            (*write)(stream, str, size);
            break;
        }
        case JSON_TYPE_STRING:
            _PrintString(write, stream, un->string);
            break;
        default:
            break;
    }
}

typedef struct callback_data
{
    int depth;
    int newline;
    int comma;
    json_write_t write;
    void* stream;
} callback_data_t;

json_result_t _json_print_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    callback_data_t* data = callback_data;
    json_write_t write = data->write;
    void* stream = data->stream;

    (void)parser;

    /* Print commas */
    if (reason != JSON_REASON_END_ARRAY && reason != JSON_REASON_END_OBJECT &&
        data->comma)
    {
        data->comma = 0;
        (*write)(stream, STRLIT(","));
    }

    /* Decrease depth */
    if (reason == JSON_REASON_END_OBJECT || reason == JSON_REASON_END_ARRAY)
    {
        data->depth--;
    }

    /* Print newline */
    if (data->newline)
    {
        data->newline = 0;
        (*write)(stream, STRLIT("\n"));
        _Indent(write, stream, data->depth);
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
            _PrintString(write, stream, un->string);
            (*write)(stream, STRLIT(": "));
            data->comma = 0;
            break;
        }
        case JSON_REASON_BEGIN_OBJECT:
        {
            data->depth++;
            data->newline = 1;
            data->comma = 0;
            (*write)(stream, STRLIT("{"));
            break;
        }
        case JSON_REASON_END_OBJECT:
        {
            data->newline = 1;
            data->comma = 1;
            (*write)(stream, STRLIT("}"));
            break;
        }
        case JSON_REASON_BEGIN_ARRAY:
        {
            data->depth++;
            data->newline = 1;
            data->comma = 0;
            (*write)(stream, STRLIT("["));
            break;
        }
        case JSON_REASON_END_ARRAY:
        {
            data->newline = 1;
            data->comma = 1;
            (*write)(stream, STRLIT("]"));
            break;
        }
        case JSON_REASON_VALUE:
        {
            data->newline = 1;
            data->comma = 1;
            json_print_value(write, stream, type, un);
            break;
        }
    }

    /* Final newline */
    if (reason == JSON_REASON_END_OBJECT || reason == JSON_REASON_END_ARRAY)
    {
        if (data->depth == 0)
            (*write)(stream, STRLIT("\n"));
    }

    return JSON_OK;
}

json_result_t json_print(
    json_write_t write,
    void* stream,
    const char* json_data,
    size_t json_size,
    json_allocator_t* allocator)
{
    json_result_t result = JSON_UNEXPECTED;
    char* data = NULL;
    json_parser_t parser_buf;
    json_parser_t* parser = &parser_buf;
    callback_data_t callback_data = {0, 0, 0, write, stream};

    _memset(&parser_buf, 0, sizeof(parser_buf));

    if (!write || !json_data || !json_size)
        RAISE(JSON_BAD_PARAMETER);

    if (!allocator || !allocator->ja_malloc || !allocator->ja_free)
        return JSON_BAD_PARAMETER;

    if (!(data = allocator->ja_malloc(json_size)))
        RAISE(JSON_OUT_OF_MEMORY);

    _memcpy(data, json_data, json_size);

    if (json_parser_init(
            parser,
            data,
            json_size,
            _json_print_callback,
            &callback_data,
            allocator) != JSON_OK)
    {
        RAISE(JSON_FAILED);
    }

    if (json_parser_parse(parser) != JSON_OK)
    {
        RAISE(JSON_BAD_SYNTAX);
    }

    if (callback_data.depth != 0)
    {
        RAISE(JSON_BAD_SYNTAX);
    }

    result = JSON_OK;

done:

    if (data)
        allocator->ja_free(data);

    return result;
}

void json_dump_path(json_write_t write, void* stream, json_parser_t* parser)
{
    if (write && parser)
    {
        size_t depth = parser->depth;

        for (size_t i = 0; i < depth; i++)
        {
            (*write)(
                stream, parser->path[i].name, _strlen(parser->path[i].name));

            if (parser->path[i].size)
            {
                strbuf_t buf;
                size_t size;
                const char* str = _i64tostr(&buf, parser->path[i].size, &size);

                (*write)(stream, STRLIT("["));
                (*write)(stream, str, size);
                (*write)(stream, STRLIT("]"));
            }

            if (i + 1 != depth)
                (*write)(stream, STRLIT("."));
        }

        (*write)(stream, STRLIT("\n"));
    }
}
