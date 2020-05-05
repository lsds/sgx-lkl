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

static void _write(void* stream, const void* buf, size_t count)
{
    fwrite(buf, 1, count, (FILE*)stream);
}

int _load_file(
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

int main(int argc, char** argv)
{
    static json_allocator_t allocator =
    {
        malloc,
        free,
    };
    char* json_data;
    size_t json_size;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s path\n", argv[0]);
        exit(1);
    }

    if (_load_file(argv[1], 1, (void**)&json_data, &json_size) != 0)
    {
        fprintf(stderr, "%s: failed to access '%s'\n", argv[0], argv[1]);
        exit(1);
    }

    if (json_print(_write, stdout, json_data, json_size, &allocator) != JSON_OK)
    {
        fprintf(stderr, "%s: json_print() failed\n", argv[0]);
        exit(1);
    }

    return 0;
}
