#ifndef ENCLAVE_STATE_H
#define ENCLAVE_STATE_H

#include <shared/sgxlkl_enclave_config.h>

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
    size_t capacity;
    bool mounted;
} sgxlkl_enclave_disk_state_t;

typedef struct
{
    uint32_t argc;
    char** argv;
    char** envp;
    Elf64_auxv_t** auxv;
} elf64_stack_t;

typedef struct sgxlkl_enclave_state
{
    sgxlkl_enclave_config_t* config;

    /* Flattened ELF64 process stack */
    elf64_stack_t elf64_stack;

    /* State of disks */
    size_t num_disk_state;
    sgxlkl_enclave_disk_state_t* disk_state;

    /* Status of libc initialization */
    _Atomic(sgxlkl_libc_state_t) libc_state;

    /* Exit status returned when LKL terminates */
    _Atomic(int) exit_status;

    sgxlkl_shared_memory_t shared_memory;
} sgxlkl_enclave_state_t;

extern sgxlkl_enclave_state_t sgxlkl_enclave_state;

#endif /* ENCLAVE_STATE_H */