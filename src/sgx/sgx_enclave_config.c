/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * Copyright 2016, 2017 TU Dresden (under SCONE source code license)
 */

#ifdef SGXLKL_HW
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "mpmc_queue.h"
#include "sgx_enclave_config.h"
#include "sgx_hostcall_interface.h"
#include "pthread_impl.h"

/* we need this initializer for signer to find this struct in the TLS image */
static __thread enclave_parms_t enclave_parms = {.base = 0xbaadf00ddeadbabe};

enclave_parms_t* get_enclave_parms() {
    // The enclave parameters are stored in thread-local storage of each
    // ethread. Early on they can be accessed at an offset added to the fs
    // segment base which stores the current thread pointer. However, later on
    // the fs base is modified to point at the TLS of the currently running
    // lthread. By then, the scheduling context has been initialised and we can
    // use it to get the address of the enclave parameter struct.
    enclave_parms_t* ret;
    if (__scheduler_self()) {
        ret = __scheduler_self()->enclave_parms;
    }

    if (!ret) {
        __asm("movq %%fs:16,%0\n" : "=r"(ret) : : );
    }

    return ret;
}

/*
 * Do not delete. This is required to prevent the thread-local variable from
 * being removed during optimization.
 */
void* never_called() {
    return &enclave_parms;
}

void* get_exit_address() {
    if (get_enclave_parms()->eh_handling)
        return (void*) get_enclave_parms()->eh_exit_addr;
    return (void*) get_enclave_parms()->exit_addr;
}

uint64_t get_ursp() {
    if (get_enclave_parms()->eh_handling)
        return get_enclave_parms()->eh_ursp;
    return get_enclave_parms()->ursp;
}

uint64_t get_urbp() {
    if (get_enclave_parms()->eh_handling)
        return get_enclave_parms()->eh_urbp;
    return get_enclave_parms()->urbp;
}

uint64_t get_eh_handling() {
    return get_enclave_parms()->eh_handling;
}

void set_eh_handling(uint64_t val) {
    get_enclave_parms()->eh_handling = val;
}

int get_thread_state() {
    return get_enclave_parms()->thread_state;
}

void set_thread_state(int state) {
    get_enclave_parms()->thread_state = state;
}

void leave_enclave(uint64_t rdi, uint64_t rsi) {
    set_thread_state(OUTSIDE);
    void* exit_address = get_exit_address();
    uint64_t ursp = get_ursp();
    uint64_t urbp = get_urbp();
    if (setjmp(get_enclave_parms()->regs) == 0) {
        //TODO: clear registers
        __asm__ volatile(
                "mov %0,%%rsp\n"
                "mov %1,%%rbp\n"
                ".byte 0x0f \n"
                ".byte 0x01 \n"
                ".byte 0xd7 \n"
                :
                : "r"(ursp), "r"(urbp), "a"(0x4), "b"(exit_address), "D"(rdi), "S"(rsi)
                :
        );
    }
    set_thread_state(ACTIVE);
}

void exit_enclave(uint64_t rdi, uint64_t rsi, void* exit_address, int exit_thread_state) {
    set_thread_state(exit_thread_state);
    uint64_t ursp = get_ursp();
    uint64_t urbp = get_urbp();
    if (get_eh_handling()) set_eh_handling(0);
    //TODO: clear registers
    __asm__ volatile(
        "mov %0,%%rsp\n"
        "mov %1,%%rbp\n"
        ".byte 0x0f \n"
        ".byte 0x01 \n"
        ".byte 0xd7 \n"
        :
        : "r"(ursp), "r"(urbp), "a"(0x4), "b"(exit_address), "D"(rdi), "S"(rsi)
        :
        );
}

void ereport(void *target, char *report_data, char *report)  {
    __asm__ volatile(
            ".byte 0x0f \n"
            ".byte 0x01 \n"
            ".byte 0xd7 \n"
            :
            : "a"(0x0),         // EAX = 00H ENCLU[EREPORT]
              "b"(target),      // RBX = Address of TARGETINFO (In)
              "c"(report_data), // RCX = Address of REPORTDATA (In)
              "d"(report)       // RDX = Address where the REPORT is
                                //       written to
            :
            );
}



/* Exit enclave to do cpuid
 * TODO: We should do sanity checks on return values
 * Input: unsigned int request[4], eax in request[0], ecx in request[2]
 * Output: values of eax, ebx, ecx, edx returned by cpuid in corresponding elements of request array */
void ocall_cpuid(unsigned int* request) {
    if (request == NULL) return;
    Arena *a = NULL;
    getsyscallslot(&a);
    size_t len = sizeof(*request) * 4;
    void* req = arena_alloc(a, len) ;
    if (req != NULL) memcpy(req, request, len);
    leave_enclave(SGXLKL_EXIT_CPUID, (uint64_t) req);
    if (req != NULL) memcpy(request, req, len);
    arena_free(a);
}

/* Handle CPUID ecall after an illegal instruction has been caught on the host */
void ecall_cpuid(gprsgx_t *regs) {
    unsigned int request[4];
    int clear_tsc = 0;
    request[0] = (unsigned int)regs->rax;
    request[2] = (unsigned int)regs->rcx;
    if (request[0] == 1) clear_tsc = 1;
    ocall_cpuid(request);
    if (clear_tsc) {
        /* clear TSC bit in edx, CPUID_FEAT_EDX_TSC - 5th bit */
        unsigned int mask;
        mask = ~(1<<4);
        request[3] &= mask;
    }
    regs->rax = request[0];
    regs->rbx = request[1];
    regs->rcx = request[2];
    regs->rdx = request[3];
    regs->rip += 2;
}

/* Handle RDTSC ecall after an illegal instruction has been caught on the host */
void ecall_rdtsc(gprsgx_t *regs, uint64_t ts) {
    uint64_t mask;
    mask = 0xffffffff;
    regs->rax = ts & mask;
    regs->rdx = (ts & ~mask) >> 32;
    regs->rip += 2;

}

int in_enclave_range(void *addr, size_t len) {
    char *encl_start = (char *) get_enclave_parms()->base;
    char *encl_end = encl_start + get_enclave_parms()->enclave_size;
    return !((char *)addr >= encl_end || (char *)addr + len <= encl_start);
}

static void enclave_config_fail(void) {
    exit_enclave(SGXLKL_EXIT_ERROR, SGXLKL_CONFIG_ASSERT_VIOLATION, get_exit_address(), UNUSED);
}

static char *enclave_safe_str_copy(char *s) {
    char *safe_s = NULL;
    if (s) {
        size_t s_len = strlen(s);
        if (in_enclave_range(s, s_len)) enclave_config_fail();
        if (!(safe_s = strndup(s, s_len + 1)))
            enclave_config_fail();
    }

    return safe_s;
}

enclave_config_t *enclave_config_copy_and_check(enclave_config_t *untrusted) {
    enclave_config_t *encl;
    if (!(encl = malloc(sizeof(*encl)))) enclave_config_fail();
    *encl = *untrusted;

    // Check pointers

    // Panic on assertion failure. The enclave is not set up yet to print
    // anything/fail gracefully.
    // TODO Leave the enclave with exit code to indicate assertion failure?

    // Set base/heap/heapsize to known good values
    encl->base = (void*)get_enclave_parms()->base;
    encl->heap = (void*)get_enclave_parms()->heap;
    encl->heapsize = get_enclave_parms()->heap_size;

    // Must be outside enclave range
    if (in_enclave_range(encl->syscallpage, PAGE_SIZE)) enclave_config_fail();
    if (in_enclave_range(encl->syscallq, sizeof(struct mpmcq))) enclave_config_fail();
    if (in_enclave_range(encl->returnq, sizeof(struct mpmcq))) enclave_config_fail();
    if (in_enclave_range(encl->disks, sizeof(*encl->disks) * encl->num_disks)) enclave_config_fail();
    if (encl->vvar && in_enclave_range(encl->vvar, PAGE_SIZE)) enclave_config_fail();

    // TODO Should the kernel command line arguments actually be trusted at
    // all?
    // Copy kernel cmd line into enclave
    encl->kernel_cmd = enclave_safe_str_copy(encl->kernel_cmd);

    // Copy WG key and peers into enclave
    encl->wg.key = enclave_safe_str_copy(encl->wg.key);
    enclave_wg_peer_config_t *safe_peers = malloc(encl->wg.num_peers * sizeof(*safe_peers));
    for (int i = 0; i < encl->wg.num_peers; i++) {
        safe_peers[i].key = enclave_safe_str_copy(encl->wg.peers[i].key);
        safe_peers[i].allowed_ips = enclave_safe_str_copy(encl->wg.peers[i].allowed_ips);
        safe_peers[i].endpoint = enclave_safe_str_copy(encl->wg.peers[i].endpoint);
    }
    encl->wg.peers = safe_peers;

    if (in_enclave_range(encl->quote_target_info, sizeof(sgx_target_info_t))) enclave_config_fail();
    if (in_enclave_range(encl->report, sizeof(sgx_report_t))) enclave_config_fail();


    // Comments on other fields
    // encl->disks:     Individual disk configurations are checked in startmain
    // encl->auxv:      auxv is handled in init_auxv
    // encl->argv:      argv/envp are set before application launch. Host-provided
    //                  argv/envp are ignored in release mode
    // encl->app_config app config is provided remotely in release mode

    return encl;
}

void enclave_config_free(enclave_config_t *encl) {
    free(encl->kernel_cmd);
    free(encl->wg.key);
    for (int i = 0; i < encl->wg.num_peers; i++) {
        free(encl->wg.peers[i].key);
        free(encl->wg.peers[i].allowed_ips);
        free(encl->wg.peers[i].endpoint);
    }
    free(encl->wg.peers);
    free(encl);
}

#endif
