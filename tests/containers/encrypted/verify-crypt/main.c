#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char** argv)
{
    const char path[] = "/test/alphabet";
    char buf[100];
    FILE* stream;

    if (!(stream = fopen(path, "r")))
    {
        fprintf(stderr, "%s: cannot open: %s\n", argv[0], path);
        exit(1);
    }

    if (!fgets(buf, sizeof(buf), stream))
    {
        fprintf(stderr, "%s: cannot read: %s\n", argv[0], path);
        exit(1);
    }

    {
        char* p = buf + strlen(buf);

        while (p != buf && isspace(p[-1]))
            *--p = '\0';
    }

    if (strcmp(buf, "abcdefghijklmnopqrstuvwxyz") != 0)
    {
        fprintf(stderr, "%s: test failed: %s\n", argv[0], path);
        exit(1);
    }

    fclose(stream);

    printf("*******************\n");
    printf("*** passed test ***\n");
    printf("*******************\n");

    return 0;
}
