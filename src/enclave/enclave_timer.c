#include <host/sgxlkl_util.h>
#include <stdatomic.h>
#include <time.h>
#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_config.h"
#include "enclave/sgxlkl_t.h"

_Atomic(uint64_t) internal_counter = 0;

/*
 * Get the value of our internal counter to track time monotonically. Time is
 * measured outside the enclave and updates a shared memory structure. We check
 * our own internal shadow value against the external value and return a new
 * nano value that is guaranteed to grow monotonically.
 *
 * Because the external timer is only periodically updated (every 5ms as of the
 * * time this was written) multiple calls to `enclave_nanos` will result in the
 * * external nanos count ending up behind the internal view. For example:
 *
 * | Point in time | External | Internal | Result |
 * | ------------- | -------- | -------- | ------ |
 * | A             | 10       | 0        | 10     |
 * | B             | 10       | 10       | 11     |
 * | C             | 10       | 11       | 12     |
 * | D             | 15       | 12       | 15     |
 *
 */
uint64_t enclave_nanos()
{
    uint64_t e = sgxlkl_enclave->shared_memory.timer_dev_mem->nanos;
    uint64_t i = internal_counter;
    if (e > i)
    {
        if (atomic_compare_exchange_strong(&internal_counter, &i, e))
            return e;
        else
            return i;
    }
    else
    {
        return atomic_fetch_add(&internal_counter, 1);
    }
}
