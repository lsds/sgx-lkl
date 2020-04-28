/*
 * sleep-test.c
 *
 * This test checks how whether the sleep() call works correctly. A call to
 * sleep() is implemented by the underlying nanonsleep system call.
 *
 * In addition, the tests should be extended to check for sane values.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define SLEEP_DURATION 10
#define ERROR_MARGIN 1

int main(void)
{
    /* Check if the sleep duration is consistent with the returned time */

    time_t start_seconds, end_seconds;

    printf("Sleeping for %i seconds...\n", SLEEP_DURATION);

    start_seconds = time(NULL);
    sleep(SLEEP_DURATION);
    end_seconds = time(NULL);

    time_t interval = end_seconds - start_seconds;

    if ((interval + ERROR_MARGIN > SLEEP_DURATION) &&
        (interval - ERROR_MARGIN < SLEEP_DURATION))
    {
        printf(
            "TEST_PASSED (SLEEP_DURATION=%i ERROR_MARGIN=%i interval=%li)\n",
            SLEEP_DURATION,
            ERROR_MARGIN,
            interval);
    }
    else
    {
        printf(
            "TEST_FAILED (SLEEP_DURATION=%i ERROR_MARGIN=%i interval=%li)\n",
            SLEEP_DURATION,
            ERROR_MARGIN,
            interval);
        exit(1);
    }
    return 0;
}
