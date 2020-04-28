#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HW_FILE "/app/helloworld.txt"

int main(int argc, char** argv)
{
    char buf[100];
    FILE* f = fopen(HW_FILE, "r");
    if (!f)
    {
        fprintf(
            stderr, "Could not open file %s: %s\n", HW_FILE, strerror(errno));
        exit(1);
    }

    // Prints first line of file /app/helloworld.txt (max 100 characters)
    if (fgets(buf, sizeof(buf), f) == buf)
    {
        printf("%s", buf);
    }
    else
    {
        fprintf(
            stderr,
            "Could not read first line of file %s: %s\n",
            HW_FILE,
            strerror(errno));
        exit(1);
    }

    return 0;
}
