/*
 * segfault-test.c
 *
 * This simple test checks that:
 *   - a segfault in the applications results in an exit.
 *
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    int* p = NULL;
    printf("Dereferencing NULL\n");
    *p = 42;

    /* This should have exited, so outputting the below is a test failure. */
    printf("TEST FAILED (segfault)\n");

    return 0;
}