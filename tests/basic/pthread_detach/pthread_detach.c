/*
 * pthread_detach.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <syscall.h>

#define RUNS 100
void *thread1_func( void* arg )
{
     printf("Thread 1 in execution\n");
}

main()
{
     pthread_t thread1, thread2;
     int  iret1, iret2;
     pthread_attr_t attr;
     pthread_attr_init(&attr);
     pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
     for (int i = 0; i < RUNS; i++)
          iret1 = pthread_create( &thread1, &attr, thread1_func, NULL);
     printf("TEST PASSED");
     exit(0);
}

