#include "openenclave/corelibc/errno.h"

// oecore depends on dlmalloc which in turn is built against musl headers.
// musl requires __errno_location which oecore doesn't provide.
// This should be fixed in OE (by building dlmalloc against different headers).

int* __errno_location(void)
{
    return __oe_errno_location();
}
