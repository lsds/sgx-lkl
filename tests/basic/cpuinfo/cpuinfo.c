#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysinfo.h>

// Get the number of expected ethreads from the environment
int get_ethreads(unsigned int *ethreads)
{
    const char *env = getenv("SGXLKL_ETHREADS");
    if (env == NULL) {
        printf("[*] getenv: Unable to get SGXLKL_ETHREADS from environment\n");
        *ethreads = 1;
        return -1;
    }

    if (sscanf(env, "%u", ethreads) != 1) {
        printf("[*] getenv: Unable to parse SGXLKL_ETHREADS\n");
        *ethreads = 1;
        return -1;
    }

    return 0;
}

// Check the information in sysinfo
int test_sysinfo(unsigned int ethreads)
{
    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        printf("[*] sysinfo: Unable to get information\n");
        return -1;
    }

    if (si.procs != ethreads) {
        printf("[*] sysinfo: Unexpected number of cores %u (should be %u)\n",
               si.procs, ethreads);
        return -1;
    }

    return 0;
}

// Check the number of cores in cpuinfo, which should match SGXLKL_ETHREADS
int test_cpuinfo(unsigned int ethreads)
{
    int ret = 0;
    int cpu_num_ok = 0;

    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp == NULL) {
        printf("[*] cpuinfo: Unable to open /proc/cpuinfo\n");
        return -1;
    }

    size_t n = 0;
    char *line = NULL;

    while (getline(&line, &n, fp) > 0) {
        printf("%s", line);

        if (strstr(line, "cpu cores")) {
            unsigned int num_cores = 0;
            if (sscanf(line, "cpu cores       : %u", &num_cores) != 1) {
                printf("[*] cpuinfo: Failed to sscanf cpu cores information\n");
                ret = -1;
                break;
            }
            if (num_cores != ethreads) {
                printf("[*] cpuinfo: Unexpected number of cores %u (should be %u)\n",
                       num_cores, ethreads);
                ret = -1;
                break;
            } else {
                cpu_num_ok = 1;
            }
        }
    }

    free(line);
    fclose(fp);

    if (!cpu_num_ok) {
        ret = -1;
    }

    return ret;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    unsigned int ethreads = 1;

    if (argc != 2) {
        printf("[*] argv: Didn't get number of ethreads\n");
        ret = -1;
    } else {
        if (sscanf(argv[1], "%u", &ethreads) != 1) {
            printf("[*] argv: Unable to parse\n");
            ret = -1;
        }
    }

    printf("[*] Running test for %u ethreads\n", ethreads);

    if (test_sysinfo(ethreads) != 0)
        ret = -1;

    if (test_cpuinfo(ethreads) != 0)
        ret = -1;

    if (ret == 0) {
        printf("TEST SUCCEEDED\n");
    } else {
        printf("TEST FAILED\n");
    }

    return ret;
}
