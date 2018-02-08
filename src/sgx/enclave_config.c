/*
 * Copyright 2016, 2017, 2018 Imperial College London (under GNU General Public License v3)
 * Copyright 2016, 2017 TU Dresden (under SCONE source code license)
 */

#ifdef SGXLKL_HW
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "enclave_config.h"
#include "hostsyscallclient.h"

/* we need this initializer for signer to find this struct in the TLS image */
static __thread enclave_parms_t enclave_parms = {.base = 0xbaadf00ddeadbabe};

__attribute__((inline))
enclave_parms_t* get_enclave_parms() {
    enclave_parms_t* ret;
    __asm("movq %%fs:16,%0\n" : "=r"(ret) : : );
    return ret;
}

/*
 * Do not delete. This is required to prevent the thread-local variable to be
 * removed during optimization.
 */
void* never_called() {
    return &enclave_parms;
}

void* get_exit_address() {
    if (get_enclave_parms()->eh_handling) return (void*)get_enclave_parms()->eh_exit_addr;
    return (void*)get_enclave_parms()->exit_addr;
}

uint64_t get_ursp() {
    if (get_enclave_parms()->eh_handling) return (void*)get_enclave_parms()->eh_ursp;
    return get_enclave_parms()->ursp;
}

uint64_t get_urbp() {
    if (get_enclave_parms()->eh_handling) return (void*)get_enclave_parms()->eh_urbp;
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

/* Exit enclave to do cpuid
 * TODO: We should do sanity checks on return values
 * Input: unsigned int request[4], eax in request[0], ecx in request[2]
 * Output: values of eax, ebx, ecx, edx returned by cpuid in corresponding elements of request array */
void ocall_cpuid(unsigned int* request) {
    if (request == NULL) return;
    Arena *a = NULL;
    getsyscallslot(&a);
    size_t len = sizeof(*request) * 4;
    unsigned int* req = arena_alloc(a, len) ;
    if (req != NULL) memcpy(req, request, len);
    leave_enclave(SGXLKL_EXIT_CPUID, req);
    if (req != NULL) memcpy(request, req, len);
    arena_free(a);
}

#endif
