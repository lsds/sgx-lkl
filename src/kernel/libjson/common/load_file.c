#include "load_file.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

int json_load_file(
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
