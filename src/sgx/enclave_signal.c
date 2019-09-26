/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#ifdef SGXLKL_HW
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include "sgx_enclave_config.h"
#include "enclave_signal.h"
#include "pthread_impl.h"

void ocall_cpuid(unsigned int* request);
static int handle_sigill(gprsgx_t *regs, void *arg);
static int handle_sigsegv(gprsgx_t *regs, void *arg);
static int handle_sigfpe(gprsgx_t *regs, void *arg);

void __enclave_signal_handler(gprsgx_t *regs, enclave_signal_info_t *siginfo) {
    set_eh_handling(1);

    struct lthread *lt = lthread_self();
    // Remember old state of lthread
    int lt_old_state = lt->attr.state;
    // Pin lthread
    lt->attr.state = lt->attr.state | BIT(LT_ST_PINNED);

    int ret;
    switch (siginfo->signum) {
    case SIGSEGV:
        ret = handle_sigsegv(regs, siginfo->arg);
        break;
    case SIGILL:
        ret = handle_sigill(regs, siginfo->arg);
        break;
    case SIGFPE:
        ret = handle_sigfpe(regs, siginfo->arg);
        break;
    default:
        ret = -1;
    }

    // Restore lthread state
    lt->attr.state = lt_old_state;

    if(ret != 0) {
        exit_enclave(SGXLKL_EXIT_TERMINATE, -1, get_exit_address(), UNUSED);
    } else {
        exit_enclave(SGXLKL_EXIT_DORESUME, 0, (void*)get_enclave_parms()->eh_exit_addr, UNUSED);
    }
}

static int handle_sigsegv(gprsgx_t *regs, void *arg) {
    // Copy siginfo into enclave and set all fields to 0 except for no, code,
    // and addr.
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));
    si.si_signo = ((siginfo_t *)arg)->si_signo;
    si.si_code = ((siginfo_t *)arg)->si_code;
    si.si_addr = ((siginfo_t *)arg)->si_addr;

    // We have to map the zero page in order to support position-dependent
    // executables. However, typically the zero page is not mapped by
    // applications (and we prevent it in our mmap implementation) so that the
    // expected signal code is SEGV_MAPERR and not SEGV_ACCERR.
    if (si.si_signo == SIGSEGV && si.si_addr == 0x0 && si.si_code == SEGV_ACCERR) {
        si.si_code = SEGV_MAPERR;
    }

    struct lthread *lt;
    lt = ((struct schedctx *)regs->fsbase)->sched.current_lthread;

    ucontext_t u;
    u.uc_mcontext.gregs[REG_RDI] = regs->rdi;
    u.uc_mcontext.gregs[REG_RSI] = regs->rsi;
    u.uc_mcontext.gregs[REG_RDX] = regs->rdx;
    u.uc_mcontext.gregs[REG_RCX] = regs->rcx;
    u.uc_mcontext.gregs[REG_RAX] = regs->rax;
    u.uc_mcontext.gregs[REG_RSP] = regs->rsp;
    u.uc_mcontext.gregs[REG_RBP] = regs->rbp;
    u.uc_mcontext.gregs[REG_RIP] = regs->rip;
    u.uc_mcontext.gregs[REG_R8]  = regs->r8;
    u.uc_mcontext.gregs[REG_R9]  = regs->r9;
    u.uc_mcontext.gregs[REG_R10] = regs->r10;
    u.uc_mcontext.gregs[REG_R11] = regs->r11;
    u.uc_mcontext.gregs[REG_R12] = regs->r12;
    u.uc_mcontext.gregs[REG_R13] = regs->r13;
    u.uc_mcontext.gregs[REG_R14] = regs->r14;
    u.uc_mcontext.gregs[REG_R15] = regs->r15;

    (*sigsegv_handler)(si.si_signo, &si, &u);

    /* Restore the register values to the changed values */

    regs->rdi = u.uc_mcontext.gregs[REG_RDI];
    regs->rsi = u.uc_mcontext.gregs[REG_RSI];
    regs->rdx = u.uc_mcontext.gregs[REG_RDX];
    regs->rcx = u.uc_mcontext.gregs[REG_RCX];
    regs->rax = u.uc_mcontext.gregs[REG_RAX];
    regs->rsp = u.uc_mcontext.gregs[REG_RSP];
    regs->rbp = u.uc_mcontext.gregs[REG_RBP];
    regs->rip = u.uc_mcontext.gregs[REG_RIP];
    regs->r8  = u.uc_mcontext.gregs[REG_R8];
    regs->r9  = u.uc_mcontext.gregs[REG_R9];
    regs->r10 = u.uc_mcontext.gregs[REG_R10];
    regs->r11 = u.uc_mcontext.gregs[REG_R11];
    regs->r12 = u.uc_mcontext.gregs[REG_R12];
    regs->r13 = u.uc_mcontext.gregs[REG_R13];
    regs->r14 = u.uc_mcontext.gregs[REG_R14];
    regs->r15 = u.uc_mcontext.gregs[REG_R15];

    return 0;
}

static int handle_sigfpe(gprsgx_t *regs, void *arg) {
    siginfo_t si;
    memcpy(&si, arg, sizeof(siginfo_t));

    struct lthread *lt;
    lt = ((struct schedctx *)regs->fsbase)->sched.current_lthread;

    ucontext_t u;
    u.uc_mcontext.gregs[REG_RDI] = regs->rdi;
    u.uc_mcontext.gregs[REG_RSI] = regs->rsi;
    u.uc_mcontext.gregs[REG_RDX] = regs->rdx;
    u.uc_mcontext.gregs[REG_RCX] = regs->rcx;
    u.uc_mcontext.gregs[REG_RAX] = regs->rax;
    u.uc_mcontext.gregs[REG_RSP] = regs->rsp;
    u.uc_mcontext.gregs[REG_RBP] = regs->rbp;
    u.uc_mcontext.gregs[REG_RIP] = regs->rip;
    u.uc_mcontext.gregs[REG_R8]  = regs->r8;
    u.uc_mcontext.gregs[REG_R9]  = regs->r9;
    u.uc_mcontext.gregs[REG_R10] = regs->r10;
    u.uc_mcontext.gregs[REG_R11] = regs->r11;
    u.uc_mcontext.gregs[REG_R12] = regs->r12;
    u.uc_mcontext.gregs[REG_R13] = regs->r13;
    u.uc_mcontext.gregs[REG_R14] = regs->r14;
    u.uc_mcontext.gregs[REG_R15] = regs->r15;

    (*sigfpe_handler)(si.si_signo, &si, &u);

    /* Restore the register values to the changed values */

    regs->rdi = u.uc_mcontext.gregs[REG_RDI];
    regs->rsi = u.uc_mcontext.gregs[REG_RSI];
    regs->rdx = u.uc_mcontext.gregs[REG_RDX];
    regs->rcx = u.uc_mcontext.gregs[REG_RCX];
    regs->rax = u.uc_mcontext.gregs[REG_RAX];
    regs->rsp = u.uc_mcontext.gregs[REG_RSP];
    regs->rbp = u.uc_mcontext.gregs[REG_RBP];
    regs->rip = u.uc_mcontext.gregs[REG_RIP];
    regs->r8  = u.uc_mcontext.gregs[REG_R8];
    regs->r9  = u.uc_mcontext.gregs[REG_R9];
    regs->r10 = u.uc_mcontext.gregs[REG_R10];
    regs->r11 = u.uc_mcontext.gregs[REG_R11];
    regs->r12 = u.uc_mcontext.gregs[REG_R12];
    regs->r13 = u.uc_mcontext.gregs[REG_R13];
    regs->r14 = u.uc_mcontext.gregs[REG_R14];
    regs->r15 = u.uc_mcontext.gregs[REG_R15];

    return 0;
}

static int handle_sigill(gprsgx_t *regs, void *arg) {
    uint16_t opcode = *((uint16_t*) regs->rip);
    switch (opcode) {
    /* CPUID opcode: 0f a2 */
    case 0xa20f:
        ecall_cpuid(regs);
        return 0;
    /* RDTSC opcode: 0f 31 */
    case 0x310f:
        ecall_rdtsc(regs, (uint64_t) arg);
        return 0;
    }

    /* Unhandled illegal instruction */
    return -1;
}
#endif /* SGXLKL_HW */
