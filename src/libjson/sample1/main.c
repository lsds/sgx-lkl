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

#include "structs.h"

#include <assert.h>
#include <ctype.h>
#include <json.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../common/load_file.h"
#include "strings.h"

const char* arg0;

#define COUNTOF(ARR) (sizeof(ARR) / sizeof(ARR[0]))

typedef struct json_callback_data
{
    header_t* hdr;
} json_callback_data_t;

static int _strtou64(uint64_t* x, const char* str)
{
    char* end;

    *x = strtoull(str, &end, 10);

    if (!end || *end != '\0')
        return -1;

    return 0;
}

static void _write(void* stream, const void* buf, size_t count)
{
    fwrite(buf, 1, count, (FILE*)stream);
}

static json_result_t _json_read_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    json_result_t result = JSON_UNEXPECTED;
    json_callback_data_t* data = (json_callback_data_t*)callback_data;

    switch (reason)
    {
        case JSON_REASON_NONE:
        {
            /* Unreachable */
            assert(false);
            break;
        }
        case JSON_REASON_NAME:
        {
            break;
        }
        case JSON_REASON_BEGIN_OBJECT:
        {
            break;
        }
        case JSON_REASON_END_OBJECT:
        {
            break;
        }
        case JSON_REASON_BEGIN_ARRAY:
        {
            break;
        }
        case JSON_REASON_END_ARRAY:
        {
            break;
        }
        case JSON_REASON_VALUE:
        {
            if (json_match(parser, "keyslots.#.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->type);

                if (strlcpy(ks->type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "keyslots.#.key_size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->key_size = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->kdf.type);

                if (strlcpy(ks->kdf.type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }

                if (strcmp(ks->kdf.type, "pbkdf2") != 0 &&
                    strcmp(ks->kdf.type, "argon2i") != 0 &&
                    strcmp(ks->kdf.type, "argon2id") != 0)
                {
                    result = JSON_UNSUPPORTED;
                    goto done;
                }
            }
            else if (json_match(parser, "keyslots.#.kdf.time") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->kdf.time = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.memory") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->kdf.memory = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.hash") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->kdf.hash);

                if (strlcpy(ks->kdf.hash, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "keyslots.#.kdf.iterations") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->kdf.iterations = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.cpus") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->kdf.cpus = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.salt") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                size_t n = sizeof(ks->kdf.salt);

                if (strlcpy(ks->kdf.salt, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "keyslots.#.af.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->af.type);

                if (strlcpy(ks->af.type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "keyslots.#.af.hash") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->af.hash);

                if (strlcpy(ks->af.hash, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "keyslots.#.af.stripes") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->af.stripes = un->integer;
            }
            else if (json_match(parser, "keyslots.#.area.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->area.type);

                if (strlcpy(ks->area.type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (
                json_match(parser, "keyslots.#.area.encryption") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->area.encryption);

                if (strlcpy(ks->area.encryption, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "keyslots.#.area.key_size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->area.key_size = un->integer;
            }
            else if (json_match(parser, "keyslots.#.area.offset") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];

                if (_strtou64(&ks->area.offset, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }
            }
            else if (json_match(parser, "keyslots.#.area.size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];

                if (_strtou64(&ks->area.size, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }
            }
            else if (json_match(parser, "segments.#.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->type);

                if (strlcpy(seg->type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "segments.#.offset") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_segment_t* seg = &data->hdr->segments[i];

                if (_strtou64(&seg->offset, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }
            }
            else if (json_match(parser, "segments.#.iv_tweak") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_segment_t* seg = &data->hdr->segments[i];

                if (_strtou64(&seg->iv_tweak, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }
            }
            else if (json_match(parser, "segments.#.size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_segment_t* seg = &data->hdr->segments[i];

                if (strcmp(un->string, "dynamic") == 0)
                    seg->size = (uint64_t)-1;
                else if (_strtou64(&seg->size, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }
            }
            else if (json_match(parser, "segments.#.encryption") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->encryption);

                if (strlcpy(seg->encryption, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "segments.#.sector_size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                seg->sector_size = un->integer;
            }
            else if (json_match(parser, "segments.#.integrity.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->integrity.type);

                if (strlcpy(seg->integrity.type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (
                json_match(parser, "segments.#.integrity.journal_encryption") ==
                JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->integrity.journal_encryption);
                char* p = seg->integrity.journal_encryption;

                if (strcmp(un->string, "none") != 0)
                {
                    result = JSON_UNSUPPORTED;
                    goto done;
                }

                if (strlcpy(p, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (
                json_match(parser, "segments.#.integrity.journal_integrity") ==
                JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->integrity.journal_integrity);
                char* p = seg->integrity.journal_integrity;

                if (strcmp(un->string, "none") != 0)
                {
                    result = JSON_UNSUPPORTED;
                    goto done;
                }

                if (strlcpy(p, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "digests.#.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                const size_t n = sizeof(digest->type);

                if (strcmp(un->string, "pbkdf2") != 0)
                {
                    result = JSON_UNSUPPORTED;
                    goto done;
                }

                if (strlcpy(digest->type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "digests.#.keyslots") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;
                uint64_t n;

                if (type != JSON_TYPE_STRING || i >= NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_digest_t* digest = &data->hdr->digests[i];

                if (_strtou64(&n, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                if (n >= COUNTOF(digest->keyslots))
                {
                    result = JSON_OUT_OF_BOUNDS;
                    goto done;
                }

                digest->keyslots[n] = 1;
            }
            else if (json_match(parser, "digests.#.segments") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;
                uint64_t n;

                if (type != JSON_TYPE_STRING || i >= NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_digest_t* digest = &data->hdr->digests[i];

                if (_strtou64(&n, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                if (n >= COUNTOF(digest->segments))
                {
                    result = JSON_OUT_OF_BOUNDS;
                    goto done;
                }

                digest->segments[n] = 1;
            }
            else if (json_match(parser, "digests.#.hash") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                const size_t n = sizeof(digest->hash);

                if (strlcpy(digest->hash, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "digests.#.iterations") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                digest->iterations = un->integer;
            }
            else if (json_match(parser, "digests.#.salt") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                size_t n = sizeof(digest->salt);

                if (strlcpy(digest->hash, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "digests.#.digest") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                size_t n = sizeof(digest->digest);

                if (strlcpy(digest->hash, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    goto done;
                }
            }
            else if (json_match(parser, "config.json_size") == JSON_OK)
            {
                luks2_config_t* config = &data->hdr->config;

                if (_strtou64(&config->json_size, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }
            }
            else if (json_match(parser, "config.keyslots_size") == JSON_OK)
            {
                luks2_config_t* config = &data->hdr->config;

                if (_strtou64(&config->keyslots_size, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    goto done;
                }
            }
            else
            {
                json_dump_path(_write, stdout, parser);
                result = JSON_UNKNOWN_VALUE;
                goto done;
            }

            break;
        }
    }

    result = JSON_OK;

done:
    return result;
}

static void _parse(const char* path)
{
    json_parser_t parser;
    char* data;
    size_t size;
    json_result_t r;
    header_t header;
    json_callback_data_t callback_data = {&header};
    static json_allocator_t allocator = {
        malloc,
        free,
    };

    memset(&header, 0, sizeof(header));

    if (json_load_file(path, 1, (void**)&data, &size) != 0)
    {
        fprintf(stderr, "%s: failed to access '%s'\n", arg0, path);
        exit(1);
    }

    const json_parser_options_t options = {1};

    if ((r = json_parser_init(
             &parser,
             data,
             size,
             _json_read_callback,
             &callback_data,
             &allocator,
             &options)) != JSON_OK)
    {
        fprintf(stderr, "%s: json_parser_init() failed: %d\n", arg0, r);
        exit(1);
    }

    if ((r = json_parser_parse(&parser)) != JSON_OK)
    {
        fprintf(stderr, "%s: json_parser_init() failed: %d\n", arg0, r);
        exit(1);
    }

    if (parser.depth != 0)
    {
        fprintf(stderr, "%s: unterminated objects\n", arg0);
        exit(1);
    }

    /* check a couple of the fields */
    assert(strcmp(header.keyslots[0].area.type, "raw") == 0);
    assert(strcmp(header.keyslots[0].kdf.type, "argon2i") == 0);
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
