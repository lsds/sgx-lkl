#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/timeb.h>

#define BOTH_WAYS   1

long int get_time()
{
    struct timeb t;
    
    ftime(&t);
    return t.time;
}

long int print_time()
{
    struct timeb t;
    
    ftime(&t);
    printf("%ld.%03d:  ", t.time, t.millitm);
    return t.time;
}

int timeToDie = 0;
pthread_t main_tid;
pthread_t first_tid, second_tid;                                            

// counts of how may signals of type USR1 and USR2 each thread saw

int first_t1_hit_count = 0; // first signal first thread
int first_t2_hit_count = 0; // first signal second thread
int first_main_hit_count = 0; // first signal main thread

void handle_first_signal(int val)
{
    pthread_t tid = pthread_self();
    const char *which = NULL;
    if (tid == first_tid) {
	    first_t1_hit_count++;
        which = "first thread";
    } else if (tid == second_tid) {
	    first_t2_hit_count++;
        which = "second thread";
    } else if (tid == main_tid) {
        first_main_hit_count++;
        which = "main thread";
    } else {
	    printf("Ouch!\n");
        which = "unknown thread";
    }

    print_time();
    printf("First: got signal %d in %s %08lx\n", val, which, (unsigned long)tid);
}

int second_t1_hit_count = 0;
int second_t2_hit_count = 0;
int second_main_hit_count = 0;

void handle_second_signal(int val)
{
    pthread_t tid = pthread_self();
    const char *which = NULL;
    if (tid == first_tid) {
	    second_t1_hit_count++;
        which = "first thread";
    } else if (tid == second_tid) {
	    second_t2_hit_count++;
        which = "second thread";
    } else if (tid == main_tid) {
        second_main_hit_count++;
        which = "main thread";
    } else {
	    printf("Ouch!\n");
        which = "unknown thread";
    }
;
    print_time();
    printf("Second: got signal %d in %s %08lx\n", val, which, (unsigned long)tid);
}

volatile int stuff = 123;
volatile int stuff_counter = 10000000;

int first_t1_sent_count = 0;
int first_t2_sent_count = 0;

void *first_thread_func(void *arg)
{
    pthread_t tid = pthread_self();
    int signalID = SIGUSR1;
    printf("running first thread id %08lx\n", (unsigned long)tid);
    while (!timeToDie) {
        usleep(66666);
        // send a signal to the main thread - this kills us via lkl_bug at line 90 in cpu.c if (cpu.count > 1) fails
        print_time();
    	printf("First sending %d to %08lx (the main thread)\n", signalID, (unsigned long)main_tid);
        pthread_kill(main_tid, signalID);
        for (int i=0; i<stuff_counter; i++)
            stuff += i;
        
        // send a signal to this thread
#if BOTH_WAYS
        print_time();
    	printf("First sending %d to %08lx (first thread)\n", signalID, (unsigned long)first_tid);
        pthread_kill(first_tid, signalID);
	    first_t1_sent_count++;
#endif
        print_time();
    	printf("First sending %d to %08lx (second thread)\n", signalID, (unsigned long)second_tid);
        pthread_kill(second_tid, signalID);
	    first_t2_sent_count++;
    }
}

int second_t1_sent_count = 0;
int second_t2_sent_count = 0;

void *second_thread_func(void *arg)
{
    pthread_t tid = pthread_self();
    int signalID = SIGUSR2;
    printf("running second thread id %08lx\n", (unsigned long)tid);
    while (!timeToDie) {
        //printf("second tick\n");
        usleep(77777);
        // send a signal to the main thread - this kills us via lkl_bug at line 90 in cpu.c if (cpu.count > 1) fails
        print_time();
    	printf("Second sending %d to %08lx (the main thread)\n", signalID, (unsigned long)main_tid);
        pthread_kill(main_tid, signalID);
        for (int i=0; i<stuff_counter; i++)
            stuff += i;
        
        // send a signal to this thread
        print_time();
        printf("Second sending %d to %08lx (first thread)\n", signalID, (unsigned long)first_tid);
        pthread_kill(first_tid, signalID);
        second_t1_sent_count++;

#if BOTH_WAYS
        print_time();
        printf("Second sending %d to %08lx (second thread)\n", signalID, (unsigned long)second_tid);
        pthread_kill(second_tid, signalID);
        second_t2_sent_count++;
#endif
    }
}


int main(int argc, char** argv)
{
    long int startTime = print_time();
    int done = 0;

    main_tid = pthread_self();

    printf("Main thread id %08lx\n", (unsigned long)main_tid);	
    signal(SIGUSR1, handle_first_signal);
    signal(SIGUSR2, handle_second_signal);
    
    if (pthread_create(&first_tid, NULL, first_thread_func, NULL) == 0 &&
    	pthread_create(&second_tid, NULL, second_thread_func, NULL) == 0) {
        printf("created first thread id %08lx\n", (unsigned long)first_tid);
        printf("created second thread id %08lx\n", (unsigned long)second_tid);

        while (!done) {
    		long int now = get_time();
    		if (now - startTime > 3)
    		    done = 1;
            printf("sleeping\n");        
            usleep(100000);   // will return either after about a 100ms or at the next signal
        }
        printf("leaving\n");
        timeToDie = 1;
        pthread_join(first_tid, NULL);
        pthread_join(second_tid, NULL);
    }

    printf("counts:\n");

    printf("   SIGUSR1 sent to/recieved by thread 1: %d/%d delta %d\n", first_t1_sent_count, first_t1_hit_count, first_t1_sent_count - first_t1_hit_count);
    printf("   SIGUSR2 sent to/recieved by thread 1: %d/%d delta %d\n", second_t1_sent_count, second_t1_hit_count, second_t1_sent_count - second_t1_hit_count);

    printf("   SIGUSR1 sent to/recieved by thread 2: %d/%d delta %d\n", first_t2_sent_count, first_t2_hit_count, first_t2_sent_count - first_t2_hit_count);
    printf("   SIGUSR2 sent to/recieved by thread 2: %d/%d delta %d\n", second_t2_sent_count, second_t2_hit_count, second_t2_sent_count - second_t2_hit_count);
    printf("   recieved by main SIGUSR1/SIGUSR2: %d/%d\n", first_main_hit_count, second_main_hit_count);

    printf("Goodbye\n");
    return 0;
}
