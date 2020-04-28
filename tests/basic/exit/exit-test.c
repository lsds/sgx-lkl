/*
 * exit-test.c
 *
 * This simple test checks that:
 *   - the exit syscall works correctly.
 *
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    printf("Calling exit(42)...\n");
    exit(42);

    /* This should have exited, so outputting the below is a test failure. */
    printf("TEST FAILED (exit)\n");

    return 0;
}