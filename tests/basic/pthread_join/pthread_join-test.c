/*
 * pthread_join-test.c
 *
 * This simple test checks that thread creation and joining
 * behaves as expected when run in sequence.
 *
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define ARRAY_SIZE 100000
#define ITERATIONS 50000
#define RUNS 10000
#define PRINT_MOD 1000

#define printf_mod(x, ...)        \
    if (i % PRINT_MOD == 0)       \
    {                             \
        printf(x, ##__VA_ARGS__); \
    }

typedef struct
{
    int* a;
    long n;
} subarray;

void* thread_worker(void* arg)
{
    long i;

    for (i = 0; i < ((subarray*)arg)->n; i++)
        ((subarray*)arg)->a[i]++;

    /*
     * The following getpid() does an LKL system call in this lthread,
     * causing an allocation/dealloction of the associated LKL host
     * thread.
     */
    pid_t pid = getpid();
    if (pid < 0)
    {
        printf("Did not get valid pid (pid=%i)\n", pid);
        printf("TEST FAILED\n");
        exit(-1);
    }
}

int main(void)
{
    int i;
    int a[ARRAY_SIZE];
    pthread_t thread1;
    subarray subarray1;
    int ret;

    subarray1.a = &a[0];
    subarray1.n = ITERATIONS;

    for (i = 0; i < RUNS; i++)
    {
        printf_mod("Creating worker thread (run=%i)\n", i);
        ret = pthread_create(&thread1, NULL, thread_worker, &subarray1);
        if (ret != 0)
        {
            printf("Failed to create thread (ret=%i)\n", ret);
            printf("TEST FAILED\n");
            exit(-1);
        }

        printf_mod("Joining worker thread...\n");
        int ret = pthread_join(thread1, NULL);
        if (ret != 0)
        {
            printf("Failed to join thread (ret=%i)\n", ret);
            printf("TEST FAILED\n");
            exit(-1);
        }
        printf_mod("Thread joined (ret=%i, run=%i)\n", ret, i);
    }

    if (i == RUNS)
    {
        printf("TEST PASSED (pthread_join) runs=%i\n", i);
    }
    else
    {
        printf("Wrong number of runs\n");
        printf("TEST FAILED\n");
    }

    return 0;
}