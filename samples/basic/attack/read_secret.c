#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HW_FILE "/secret.txt"

int main(int argc, char** argv)
{
    char buf[100];
    FILE* f = fopen(HW_FILE, "r");
    if (!f)
    {
        fprintf(
            stderr, "Could not open file %s: %s\n", HW_FILE, strerror(errno));
        fprintf(stderr, "TEST_FAILED");
        exit(1);
    }

    if (fgets(buf, sizeof(buf), f) != buf)
    {
        fprintf(
            stderr,
            "Could not read first line of file %s: %s\n",
            HW_FILE,
            strerror(errno));
        exit(1);
    }
    printf("Ready to be attacked...\n");
    sleep(30);
    return 0;
}
