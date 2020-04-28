/*
 * raise-test.c
 *
 * This simple test checks that:
 *   - the raise syscall works correctly and the enclave
 *     aborts with an unhandled signal.
 *
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static const int sig_to_raise = SIGTERM;

static bool signal_received = false;

void signal_handler(int sig)
{
    printf("Received signal=%i\n", sig);
    signal_received = true;
}

int main(void)
{
    printf("Executing pid system call... ");
    int pid = getpid();
    printf("pid=%i\n", pid);

    if (pid == 1)
    {
        printf("TEST FAILED (raise): running as pid 1\n");
    }

    printf("Registering signal handler...\n");
    signal(sig_to_raise, signal_handler);

    printf("Calling raise(%i)... should call signal handler\n", sig_to_raise);
    raise(sig_to_raise);

    if (!signal_received)
    {
        printf("TEST FAILED (raise): signal handler not called\n");
    }

    printf("Removing signal handler\n");
    signal(sig_to_raise, SIG_DFL);

    printf("Calling raise(%i)... should abort test\n", sig_to_raise);
    raise(sig_to_raise);

    /*
     * Th test should have exited, so outputting the line below is a
     * test failure.
     */
    printf("TEST FAILED (raise)\n");

    return 0;
}