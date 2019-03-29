
#ifndef SGX_ENCLAVE_CONFIG_H
#define SGX_ENCLAVE_CONFIG_H

#include <netinet/ip.h>
#include <inttypes.h>
#include <stdlib.h>
#include <elf.h>
#include "mpmc_queue.h"
//#include "ring_buff.h"

#ifdef SGXLKL_HW
#include <setjmp.h>
#include <pthread.h>
#endif

/* Mode (SIM/HW) */
#define SGXLKL_HW_MODE  0
#define SGXLKL_SIM_MODE 1

typedef struct {
    uintptr_t arg1;
    uintptr_t arg2;
    uintptr_t arg3;
    uintptr_t arg4;
    uintptr_t arg5;
    uintptr_t arg6;
    union {
        uintptr_t syscallno; // Set at request time
        uintptr_t ret_val; // Set at response time
    };
    uintptr_t status;
} syscall_t __attribute__((aligned(64)));

/* Maximum path length of mount points for secondary disks */
#define SGXLKL_DISK_MNT_MAX_PATH_LEN 255

typedef struct enclave_disk_config {
    int fd;
    char mnt[SGXLKL_DISK_MNT_MAX_PATH_LEN + 1];
    int ro;
    int enc;
    char *key;
    size_t key_len;
    char *roothash;
    size_t roothash_offset;
    size_t capacity;
    char *mmap;
} enclave_disk_config_t;

/* Untrusted config provided by the user */
typedef struct enclave_config {
    void *syscallpage;
    size_t maxsyscalls;
    size_t max_user_threads;
    void *heap;
    size_t heapsize;
    size_t stacksize;
    struct mpmcq syscallq;
    struct mpmcq returnq;
    size_t num_disks;
    struct enclave_disk_config *disks; /* Array of disk configurations, length = num_disks */
    int net_fd;
    struct in_addr net_ip4;
    struct in_addr net_gw4;
    int net_mask4;
    char hostname[32];
    char **argv;
    int argc;
    Elf64_auxv_t* auxv;
    void* base; /* Base address of lkl/libc code */
    void *(*ifn)(struct enclave_config *);
    size_t backoff_factor;
    unsigned backoff_maxpause;
    long sysconf_nproc_conf;
    long sysconf_nproc_onln;
    void *shm_common;
    void *shm_enc_to_out;
    void *shm_out_to_enc;
    int mode; /* SGXLKL_HW_MODE or SGXLKL_SIM_MODE */
    void *vvar;
    int fsgsbase; /* Can we use FSGSBASE instructions within the enclave? */
#ifndef SGXLKL_HW
    void (*sim_exit_handler) (int);
#endif
} enclave_config_t;

enum SlotState { DONE, WRITTEN };
enum Pointers { READ_P, READY_P, WRITE_P};


#ifdef SGXLKL_HW

typedef struct {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
    uint64_t ursp;
    uint64_t urbp;
    uint32_t exitinfo;
    uint32_t reserved;
    uint64_t fsbase;
    uint64_t gsbase;
} gprsgx_t;


/*
 * States for each kernel thread (TCS):
 * UNUSED - enclave cannot be entered using this TCS
 * AVAILABLE - enclave allows entry using this TCS
 * ACTIVE - thread executes, cannot be entered (SGX should prevent this by blocking TCS)
 * OUTSIDE - thread executes/sleeps outside, allows re-entry
 */
typedef enum { ACTIVE = 0, OUTSIDE = 1, UNUSED = 2, AVAILABLE = 3 } thread_states_t;

/*
 * In-calls
 * These values are used in sgxcrt.c directly. Adjust when making changes here.
 */
#define SGXLKL_ENTER_THREAD_CREATE    0
#define SGXLKL_ENTER_SYSCALL_RESUME   1
#define SGXLKL_ENTER_HANDLE_SIGNAL    2

/* Exit reasons */
#define SGXLKL_EXIT_TERMINATE        0
#define SGXLKL_EXIT_SYSCALL          1
#define SGXLKL_EXIT_ERROR            2
#define SGXLKL_EXIT_SLEEP            3
#define SGXLKL_EXIT_CPUID            4
#define SGXLKL_EXIT_DORESUME         5

/* Error codes */
#define SGXLKL_UNEXPECTED_CALLID     1

/* Enclave parameters, maintained within enclave */
typedef struct {
    uint64_t base;
    uint64_t heap;
    uint64_t stack;
    uint64_t ossa;
    uint64_t tcsn;
    uint64_t heap_size;
    uint64_t exit_addr;
    uint64_t ursp;
    uint64_t urbp;
    uint64_t stack_size;
    uint64_t enclave_size;
    uint64_t tid;
    uint64_t tls_vaddr;
    uint64_t tls_filesz;
    uint64_t tls_memsz;
    uint64_t thread_state;
    uint64_t eh_tcs_addr;
    uint64_t eh_exit_addr;
    uint64_t eh_ursp;
    uint64_t eh_urbp;
    uint64_t eh_handling;
    jmp_buf  regs;
} enclave_parms_t;

void     threads_init();
uint64_t get_ursp();
uint64_t get_urbp();
void     exit_enclave(uint64_t rdi, uint64_t rsi, void* exit_address, int exit_thread_state);
void     leave_enclave(uint64_t rdi, uint64_t rsi);
void*    get_exit_address();
int      get_thread_state();
void     set_thread_state(int state);
int      set_thread_state_atomic(int thread_id, int current_state, int target_state);
void     thread_longjmp();
int      thread_setjmp();
enclave_parms_t* get_enclave_parms();
uint64_t get_eh_handling();
void     set_eh_handling(uint64_t val);

void ecall_cpuid(gprsgx_t *regs);
void ecall_rdtsc(gprsgx_t *regs, uint64_t ts);

#endif

#endif /* SGX_ENCLAVE_CONFIG_H */
