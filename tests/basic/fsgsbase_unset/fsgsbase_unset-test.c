/*
 * fsgsbase_unset-test.c
 *
 * This test checks that thread-local storage works as expected
 * when FSGSBASE is set to 0 when running SGX-LKL.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

const int num_threads = 100;
const int max_count = 1000;
_Thread_local int count = 0;

void* thread_worker(void* arg)
{
    for (int i = 0; i < max_count; i++)
        count++;
    if (count != max_count)
    {
        printf("count != max_count\n");
        printf("TEST FAILED\n");
        exit(-1);
    }
}

int main(void)
{
    int ret;
    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++)
    {
        ret = pthread_create(&threads[i], NULL, thread_worker, NULL);
        if (ret != 0)
        {
            printf("Failed to create thread (ret=%i)\n", ret);
            printf("TEST FAILED\n");
            exit(-1);
        }
    }
    for (int i = 0; i < num_threads; i++)
    {
        ret = pthread_join(threads[i], NULL);
        if (ret != 0)
        {
            printf("Failed to join thread (ret=%i)\n", ret);
            printf("TEST FAILED\n");
            exit(-1);
        }
    }
    printf("TEST PASSED\n");
    return 0;
}