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

    if (getenv(name) == NULL)
    {
        res = -1;
        printf("\nEnvironment variable %s has not been set, enter value: \n", name);
        fflush(stdout);
        char* s = fgets(str, buf_size, stdin);
        if (s)
        {
            size_t len = strlen(s);
            if (len > 0)
            {
                // Remove trailing '\n'
                s[len - 1] = '\0';
            }
            res = setenv(name, s, 0);
            if (res != 0)
            {
                printf(FAILMSG("\nSetting environment variable %s failed.\n"), name);
                goto fail;
            }
        }
        else
        {
            printf(FAILMSG("Fail to get value for environment variable %s from console."), name);
            goto fail;
        }
    }

    return getenv(name);

fail:
    return NULL;
}
