#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#define TEST_VARIANCE 2

void clock_settime_to(time_t clock_seconds)
{
    struct timespec ts;
    ts.tv_sec = clock_seconds;
    ts.tv_nsec = 0;
    if (clock_settime(CLOCK_REALTIME, &ts) != 0)
    {
      printf("FAILED to update realtime clock to %ld seconds via clock_settime. errno: %d\n", clock_seconds, errno);
      exit(1);
    }
}

void gettimeofday_test(time_t test_value)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
    {
        printf("FAILED: gettimeofday call failed. errno: %d\n", errno);
        exit(1);
    }

    if (tv.tv_sec < test_value)
    {
        printf("FAILED: realtime clock seconds %ld is less than %ld seconds after being set\n", tv.tv_sec, test_value);
        exit(1);
    }

    if (tv.tv_sec > (test_value + TEST_VARIANCE))
    {
        printf("FAILED: realtime clock seconds %ld is outside variance after being set to %ld\n", tv.tv_sec, test_value);
        exit(1);
    }
}

void clock_gettime_test(time_t test_value)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        printf("FAILED: clock_gettime call failed. errno: %d\n", errno);
        exit(1);
    }

    if (ts.tv_sec < test_value)
    {
        printf("FAILED: realtime clock seconds %ld is less than %ld seconds after being set\n", ts.tv_sec, test_value);
        exit(1);
    }

    if (ts.tv_sec > (test_value + TEST_VARIANCE))
    {
        printf("FAILED: realtime clock seconds %ld is outside variance after being set to %ld\n", ts.tv_sec, test_value);
        exit(1);
    }
}

void clock_settime_test(time_t clock_seconds)
{
    /* Set to to a known time via clock_settime and then verify that both...
     * - gettimeofday
     * - clock_getime
     * return the "correct" time where "correct" is within a variance defined
     * by TEST_VARIANCE
     */

    clock_settime_to(clock_seconds);
    gettimeofday_test(clock_seconds);
    clock_gettime_test(clock_seconds);
}

int main(int argc, char **argv)
{
    time_t time_one = 47260800;
    time_t time_two = 615340800;
    time_t time_three = 1000166400;
    time_t time_four = 962496000;

    printf("Running clock_settime tests\n");
    clock_settime_test(time_one);
    clock_settime_test(time_two);
    clock_settime_test(time_three);
    clock_settime_test(time_four);

    return 0;
}

