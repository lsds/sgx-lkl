/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * Copyright 2016, 2017 TU Dresden (under SCONE open source license)
 * 
 * This file is part of SGX-LKL.
 * 
 * SGX-LKL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SGX-LKL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SGX-LKL.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef SGXLKL_HW
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include "enclave_config.h"
#include "enclave_signal.h"
#include "pthread_impl.h"

void ocall_cpuid(unsigned int* request);
static int handle_sigill(gprsgx_t *regs, void *arg);
static int handle_sigsegv(gprsgx_t *regs, void *arg);

void __enclave_signal_handler(gprsgx_t *regs, enclave_signal_info_t *siginfo) {
    set_eh_handling(1);

    int ret;
    switch (siginfo->signum) {
    case SIGSEGV:
        ret = handle_sigsegv(regs, siginfo->arg);
        break;
    case SIGILL:
        ret = handle_sigill(regs, siginfo->arg);
        break;
    default:
        ret = -1;
    }

    if(ret != 0) {
        exit_enclave(SGXLKL_EXIT_TERMINATE, -1, get_exit_address(), UNUSED);
    } else {
        exit_enclave(SGXLKL_EXIT_DORESUME, 0, (void*)get_enclave_parms()->eh_exit_addr, UNUSED);
    }
}

static int handle_sigsegv(gprsgx_t *regs, void *arg) {
    siginfo_t si; 
    memcpy(&si, arg, sizeof(siginfo_t));

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

    (*segv_handler)(si.si_signo, &si, &u);

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
    uint64_t ts = (uint64_t) arg; 
    uint64_t tcs_addr, exit_addr, ursp, urbp, ssa_start, exit;
    /* cpuid opcode: 0fa2 */
    if (((unsigned char*)(regs->rip))[0] == 0x0f && ((unsigned char*)(regs->rip))[1] == 0xa2) {
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

        return 0;
    }
    /* rdtsc opcode: 0f31 */
    else if (((unsigned char*)(regs->rip))[0] == 0x0f && ((unsigned char*)(regs->rip))[1] == 0x31) {
        uint64_t mask;
        mask = 0xffffffff;
        regs->rax = ts & mask;
        regs->rdx = (ts & ~mask) >> 32;
        regs->rip += 2;

        return 0;
    } 

    /* Unhandled illegal instruction */
    return -1;
}
#endif /* SGXLKL_HW */
