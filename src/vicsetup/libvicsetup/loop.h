#ifndef _VIC_LOOP_H
#define _VIC_LOOP_H

#include <stdint.h>
#include <stdbool.h>

#include "vic.h"

int vic_loop_attach(
    const char* path,
    uint64_t offset,
    bool readonly,
    bool autoclear,
    char dev[PATH_MAX]);

vic_result_t vic_loop_map(
    const char* path,
    char path_out[PATH_MAX],
    bool readonly);

#endif /* _VIC_LOOP_H */
