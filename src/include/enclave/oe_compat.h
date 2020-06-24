#ifndef OE_COMPAT_H
#define OE_COMPAT_H

#ifdef SGXLKL_ENCLAVE

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

#endif // SGXLKL_ENCLAVE

#endif /* OE_COMPAT_H */