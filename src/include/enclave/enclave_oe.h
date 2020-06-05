#ifndef ENCLAVE_OE_H
#define ENCLAVE_OE_H

#include "pthread_impl.h"
#include "sgxlkl_t.h"

#include "shared/enclave_config.h"
#include "shared/shared_memory.h"

// OE uses the page pointed to by %fs:0 to store thread-specific information
// for things like handling AEX and saving register state during ocalls.
// The end of this page (over 3000 bytes as of this writing) is only used by
// OE's internal pthread implementation, which SGX-LKL doesn't use. Use the
// end of this page to store the schedctx to avoid interference with OE.
#define SCHEDCTX_OFFSET (4096 - sizeof(struct schedctx))

extern void* _dlstart_c(size_t base);

extern int __libc_init_enclave(int argc, char** argv);

/* Shortcut to sgxlkl_enclave_state.enclave_config */
sgxlkl_enclave_config_t* sgxlkl_enclave;

/* Indicates different states during sgxlkl startup sequence */
typedef enum sgxlkl_libc_state
{
    libc_not_started = 0,
    libc_initializing = 1,
    libc_initialized = 2
} sgxlkl_libc_state_t;

typedef struct sgxlkl_enclave_disk_state
{
    size_t host_disk_index;
    int fd;
    char* mmap;
    size_t capacity;
    bool mounted;
} sgxlkl_enclave_disk_state_t;

typedef struct sgxlkl_enclave_state
{
    sgxlkl_enclave_config_t* enclave_config;

    size_t num_disk_state;
    sgxlkl_enclave_disk_state_t* disk_state;

    /* Status of libc initialization */
    _Atomic(sgxlkl_libc_state_t) libc_state;

    /* Exit status returned when LKL terminates */
    _Atomic(int) exit_status;

    sgxlkl_shared_memory_t shared_memory;
} sgxlkl_enclave_state_t;

extern sgxlkl_enclave_state_t sgxlkl_enclave_state;

bool sgxlkl_in_sw_debug_mode();

#endif /* ENCLAVE_OE_H */
