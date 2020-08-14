/*
 * pthread_yield.c
 *
 * This test is supposed to run with SGXLKL_ETHREADS=1 and verify
 * whether 2 threads can cooperate via yielding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <syscall.h>

void *thread1_func( void* arg )
{
     int err = sched_yield();
     printf("Thread 1 in execution\n");
     pthread_exit(NULL);
}

void *thread_func(void *arg)
{
     printf("Thread 2 in execution\n");
     pthread_exit(NULL);
}

main()
{
     pthread_t thread1, thread2;
     int  iret1, iret2;

     iret1 = pthread_create( &thread1, NULL, thread1_func, NULL);
     iret2 = pthread_create( &thread2, NULL, thread_func, NULL);

     pthread_join( thread1, NULL);
     pthread_join( thread2, NULL); 

     printf("Thread 1 returns: %d\n",iret1);
     printf("Thread 2 returns: %d\n",iret2);
     printf("TEST PASSED");
     exit(0);
}

