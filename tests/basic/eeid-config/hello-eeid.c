#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HW_FILE "/app/helloworld.txt"

void copy_file(const char* from, const char* to)
{
    FILE* from_file = fopen(from, "rb");
    FILE* to_file = fopen(to, "wb");
    if (!from_file || !to_file)
        return;
    while (!feof(from_file))
        fputc(fgetc(from_file), to_file);
    fclose(to_file);
    fclose(from_file);
}

    int main(int argc, char** argv)
    {
        char buf[100];
        FILE* f = fopen(HW_FILE, "r");
        if (!f)
        {
            fprintf(
                stderr,
                "Could not open file %s: %s\n",
                HW_FILE,
                strerror(errno));
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

        // Get attestation evidence and endorsements and write them to files.
        copy_file("/run/sgxlkl-evidence", "evidence");
        copy_file("/run/sgxlkl-endorsements", "endorsements");

        return 0;
    }
