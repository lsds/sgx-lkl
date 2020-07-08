#ifndef _JSON_LOAD_FILE_H
#define _JSON_LOAD_FILE_H

#include <stddef.h>

int json_load_file(
    const char* path,
    size_t extra_bytes,
    void** data_out,
    size_t* size_out);

#endif /* _JSON_LOAD_FILE_H */
