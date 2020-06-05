#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    const char path[] = "/app/verity-crypt.txt";
    char buf[100];
    FILE* f;

    if (!(f = fopen(path, "r")))
    {
        fprintf(stderr, "%s: cannot open: %s\n", argv[0], path);
        exit(1);
    }

    if (!fgets(buf, sizeof(buf), f))
    {
        fprintf(stderr, "%s: cannot read: %s\n", argv[0], path);
        exit(1);
    }

    printf("%s", buf);
    return 0;
}
