#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

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

    // Get attestation evidence and endorsements and write them to files.
    uint8_t* evidence = (uint8_t*)getauxval(101);
    unsigned long evidence_size = getauxval(102);
    if (evidence_size > 0)
    {
        const char* filename = "evidence.bin";
        FILE* f = fopen(filename, "w");
        size_t written = fwrite(evidence, 1, evidence_size, f);
        fclose(f);
        printf("Wrote %lu bytes to %s\n", written, filename);
    }

    uint8_t* endorsements = (uint8_t*)getauxval(103);
    unsigned long endorsements_size = getauxval(104);
    if (endorsements_size > 0)
    {
        const char* filename = "endorsements.bin";
        FILE* f = fopen(filename, "w");
        size_t written = fwrite(endorsements, 1, endorsements_size, f);
        fclose(f);
        printf("Wrote %lu bytes to %s\n", written, filename);
    }

    return 0;
}
