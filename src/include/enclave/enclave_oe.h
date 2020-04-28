#ifndef ENCLAVE_OE_H
#define ENCLAVE_OE_H

#include "pthread_impl.h"
#include "sgxlkl_t.h"

// OE uses the page pointed to by %fs:0 to store thread-specific information
// for things like handling AEX and saving register state during ocalls.
// The end of this page (over 3000 bytes as of this writing) is only used by
// OE's internal pthread implementation, which SGX-LKL doesn't use. Use the
// end of this page to store the schedctx to avoid interference with OE.
#define SCHEDCTX_OFFSET (4096 - sizeof(struct schedctx))

extern void* _dlstart_c(size_t base);

extern int __libc_init_enclave(int argc, char** argv);

sgxlkl_config_t* sgxlkl_enclave;

#endif /* ENCLAVE_OE_H */
