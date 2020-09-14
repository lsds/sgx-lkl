#ifndef __OE_TIME_INCLUDED__
#define __OE_TIME_INCLUDED__

#include "openenclave/corelibc/bits/types.h"

struct oe_tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

struct oe_tm* oe_gmtime_r(const time_t* timep, struct oe_tm* result);

uint64_t oe_get_time(void);

#endif