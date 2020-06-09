#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <syscall.h>
#include <time.h>

static int done = 0;

static void signal_handler(int sig_no)
{
    done = 1;
}

int main(int argc, char **argv)
{
    printf("STARTING\n");

    if (signal(SIGALRM, &signal_handler) == SIG_ERR)
    {
        printf("FAILED: setting up signal handler failed\n");
        exit(1);
    }

    alarm(10);

    while(!done)
    {
        struct timeval tv;
        if (gettimeofday(&tv, NULL) != 0)
        {
            printf("FAILED: gettimeofday call failed. errno: %d\n", errno);
            exit(1);
        }
        /*if (syscall(__NR_gettimeofday, &tv, NULL) != 0)
        {
            printf("FAILED: gettimeofday call failed. errno: %d\n", errno);
            exit(1);
        }*/
    }

    printf("FINISHED\n");

    return 0;
}

