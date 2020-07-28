#ifndef _OE_GENCREDS_H
#define _OE_GENCREDS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC int generate_attested_credentials(
    const char* common_name,
    size_t cert_type,
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out);

#endif /* _OE_GENCREDS_H */
