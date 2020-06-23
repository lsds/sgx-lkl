/*
 * pthread_tls.c
 *
 * This test checks thread local variables are indeed thread local.
 * It also tests pthreads conditional variables for thread synchronization.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <signal.h>

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>

__thread int tls_var;
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond1 = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond2 = PTHREAD_COND_INITIALIZER;

static void assert(int cond, const char *msg, ...)
{
	if (cond) return;
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\nTEST_FAILED\n");
	exit(-1);
}

void *parallel_workers( void* arg )
{
     const int id = (long)arg;
     tls_var = id;
     printf("[thread %d] tls_var= %d.\n", id, tls_var);
     if (id == 1) {
          printf("[thread %d] acquiring mutex1.\n", id);
          pthread_mutex_lock( &mutex1 );
          tls_var *= 2;
          sleep(2);
          printf("[thread %d] After doubling, tls_var= %d.\n", id, tls_var);
          printf("[thread %d] releasing lock. Signalling cond1.\n", id);
          pthread_mutex_unlock(&mutex1);
          pthread_cond_signal(&cond1); 

          printf("[thread %d] wait for cond2.\n", id);
          pthread_cond_wait(&cond2, &mutex2);
          printf("[thread %d] woken from cond2 wait.\n", id);
          printf("[thread %d] tls_var= %d.\n", id, tls_var);

          assert(tls_var == 2, "Thread 1 TLS var got stomped");
     } else {
          printf("[thread %d] wait for cond1.\n", id);
          pthread_cond_wait(&cond1, &mutex1);
          printf("[thread %d] woken from cond1 wait.\n", id);
          printf("[thread %d] tls_var= %d.\n", id, tls_var);

          printf("[thread %d] acquiring mutex2.\n", id);
          pthread_mutex_lock( &mutex2 );
          tls_var *= 2;
          sleep(2);
          printf("[thread %d] After doubling, tls_var= %d.\n", id, tls_var);
          printf("[thread %d] releasing lock. Signalling cond2.\n", id);
          pthread_cond_signal(&cond2); 
          pthread_mutex_unlock(&mutex2);

          assert(tls_var == 4, "Thread 2 TLS var got stomped");
     }
}

main()
{
     pthread_t thread1, thread2;
     int  iret1, iret2;
     int tnum1 = 1, tnum2 = 2;

     iret1 = pthread_create( &thread1, NULL, parallel_workers, (void*)(long)tnum1);
     iret2 = pthread_create( &thread2, NULL, parallel_workers, (void*)(long)tnum2);

     pthread_join( thread1, NULL);
     pthread_join( thread2, NULL); 

     printf("Thread 1 returns: %d\n",iret1);
     printf("Thread 2 returns: %d\n",iret2);
     printf("TEST PASSED");
     exit(0);
}

