#ifndef ENCLAVE_STATE_H
#define ENCLAVE_STATE_H

#include <elf.h>

#include <shared/sgxlkl_enclave_config.h>
#include <shared/shared_memory.h>

/* Indicates different states during sgxlkl startup sequence */
typedef enum sgxlkl_libc_state
{
    libc_not_started = 0,
    libc_initializing = 1,
    libc_initialized = 2
} sgxlkl_libc_state_t;

typedef struct sgxlkl_enclave_disk_state
{
    size_t host_disk_index; /* Index of the disk in shared memory */
    int fd;                 /* File descriptor of the disk */
    size_t capacity;        /* Capacity of the disk */
    bool mounted;           /* Tracks whether the disk has been mounted */
    uint8_t* key;           /* Encryption key */
    size_t key_len;         /* Length of encryption key */
} sgxlkl_enclave_disk_state_t;

typedef struct
{
    int argc;           /* Number of arguments */
    char** argv;        /* Arguments */
    char** envp;        /* Environment variables */
    Elf64_auxv_t* auxv; /* ELF64 auxiliary vector */
    char* data;         /* Buffer that holds all strings on the stack */
} elf64_stack_t;

typedef struct sgxlkl_enclave_state
{
    const sgxlkl_enclave_config_t* config;

    /* Flattened ELF64 process stack */
    elf64_stack_t elf64_stack;

    /* State of disks */
    size_t num_disk_state;
    sgxlkl_enclave_disk_state_t* disk_state;

    /* Status of libc initialization */
    _Atomic(sgxlkl_libc_state_t) libc_state;

    /* Exit status returned when LKL terminates */
    _Atomic(int) exit_status;

    /* Memory shared with the host */
    sgxlkl_shared_memory_t shared_memory;

    /* Flags to track whether tracing macros are currently enabled */
    struct
    {
        bool verbose;
        bool lkl_syscall;
        bool internal_syscall;
    } trace_enabled;
} sgxlkl_enclave_state_t;

extern sgxlkl_enclave_state_t sgxlkl_enclave_state;

void sgxlkl_free_enclave_state();

#endif /* ENCLAVE_STATE_H */