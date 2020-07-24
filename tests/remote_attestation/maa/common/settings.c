#include "settings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log_utils.h"

char* get_environment_variable(const char* name)
{
    const size_t buf_size = 128;
    char str[buf_size];
    int res = 0;

    if (name == NULL)
    {
        goto fail;
    }

    return getenv(name);

fail:
    return NULL;
}
