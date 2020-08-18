#ifndef OE_COMPAT_H
#define OE_COMPAT_H

#ifdef SGXLKL_ENCLAVE

/* Rewire some libc functions to oecorelibc equivalents, to avoid dependencies
 * on sgx-lkl-musl in SGX-LKL kernel space. */

#include <openenclave/corelibc/bits/types.h>
#include <openenclave/corelibc/oemalloc.h>
#include <openenclave/corelibc/oestdlib.h>
#include <openenclave/corelibc/oestring.h>
#include <openenclave/internal/safecrt.h>

#define malloc oe_malloc
#define realloc oe_realloc
#define calloc oe_calloc
#define free oe_free
#define strlen oe_strlen
#define strcmp oe_strcmp
#define strtok_r oe_strtok_r

#else

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#endif // SGXLKL_ENCLAVE

#endif /* OE_COMPAT_H */