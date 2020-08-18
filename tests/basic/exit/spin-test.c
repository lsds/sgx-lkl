/*
 * spin-test.c
 *
 * This test checks that an application can exit, even it is has another
 * thread that is in a busy loop. This means that we cannot stop that
 * thread under cooperative scheduling.
 *
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void* thread1_func(void* arg)
{
    printf("Thread 1 in busy loop...\n");

    // for (;;)
    //     ;

    return NULL;
}

int main(void)
{
    pthread_t thread1;

    printf("Creating worker thread...\n");
    int ret = pthread_create(&thread1, NULL, thread1_func, NULL);
    if (ret < 0)
    {
        printf("Failed to create thread\n");
        exit(-1);
    }

    printf("Sleeping for 1 sec...\n");
    sleep(1);

    printf("Exiting...\n");
}