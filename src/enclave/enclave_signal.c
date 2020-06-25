#include <openenclave/enclave.h>
#include "openenclave/internal/calls.h"

#include "enclave/enclave_util.h"

#include <signal.h>
#include <asm/sigcontext.h>
#include <asm-generic/ucontext.h>

#include <lkl_host.h>
#include <string.h>
#include "enclave/sgxlkl_t.h"
#include "shared/env.h"

#define RDTSC_OPCODE 0x310F

/* Mapping between OE and hardware exception */
struct oe_hw_exception_map
{
    uint32_t oe_code;  /* OE exception code */
    int trapnr;        /* Hardware trap no  */
    int signo;         /* Signal for trap   */
    bool supported;    /* Enabled in SGX-LKL */
    char* description; /* Description string */
};

/* Encapsulating the exception information to a datastructure.
 * supported field is marked a true/false based on the current
 * support. Once all signal support is enabled from OE, then
 * all entry will be marked as true.
 */
static struct oe_hw_exception_map exception_map[] = {
    {OE_EXCEPTION_DIVIDE_BY_ZERO, X86_TRAP_DE, SIGFPE, true, "SIGFPE (divide by zero)"},
    {OE_EXCEPTION_BREAKPOINT, X86_TRAP_BP, SIGTRAP, true, "SIGTRAP (breakpoint)"},
    {OE_EXCEPTION_BOUND_OUT_OF_RANGE, X86_TRAP_BR, SIGSEGV, true, "SIGSEGV (bound out of range)"},
    {OE_EXCEPTION_ILLEGAL_INSTRUCTION, X86_TRAP_UD, SIGILL, true, "SIGILL (illegal instruction)"},
    {OE_EXCEPTION_ACCESS_VIOLATION, X86_TRAP_BR, SIGSEGV, true, "SIGSEGV (access violation)"},
    {OE_EXCEPTION_PAGE_FAULT, X86_TRAP_PF, SIGSEGV, true, "SIGSEGV (page fault)"},
    {OE_EXCEPTION_X87_FLOAT_POINT, X86_TRAP_MF, SIGFPE, true, "SIGFPE (x87 floating point)"},
    {OE_EXCEPTION_MISALIGNMENT, X86_TRAP_AC, SIGBUS, true, "SIGBUS (misalignment)"},
    {OE_EXCEPTION_SIMD_FLOAT_POINT, X86_TRAP_XF, SIGFPE, true, "SIGFPE (SIMD float point)"},
};

static void _sgxlkl_illegal_instr_hook(uint16_t opcode, oe_context_t* context);

static int get_trap_details(
    uint32_t oe_code,
    struct oe_hw_exception_map* trap_map_info)
{
    int index = 0;
    int trap_map_size = ARRAY_SIZE(exception_map);

    for (index = 0; index < trap_map_size; index++)
    {
        if ((exception_map[index].oe_code == oe_code) &&
            (exception_map[index].supported == true))
        {
            *trap_map_info = exception_map[index];
            return 0;
        }
    }
    return -1;
}

static void serialize_ucontext(const oe_context_t* octx, struct ucontext* uctx)
{
    uctx->uc_mcontext.rax = octx->rax;
    uctx->uc_mcontext.rbx = octx->rbx;
    uctx->uc_mcontext.rcx = octx->rcx;
    uctx->uc_mcontext.rdx = octx->rdx;
    uctx->uc_mcontext.rbp = octx->rbp;
    uctx->uc_mcontext.rsp = octx->rsp;
    uctx->uc_mcontext.rdi = octx->rdi;
    uctx->uc_mcontext.rsi = octx->rsi;
    uctx->uc_mcontext.r8 = octx->r8;
    uctx->uc_mcontext.r9 = octx->r9;
    uctx->uc_mcontext.r10 = octx->r10;
    uctx->uc_mcontext.r11 = octx->r11;
    uctx->uc_mcontext.r12 = octx->r12;
    uctx->uc_mcontext.r13 = octx->r13;
    uctx->uc_mcontext.r14 = octx->r14;
    uctx->uc_mcontext.r15 = octx->r15;
    uctx->uc_mcontext.rip = octx->rip;
}

static void deserialize_ucontext(
    const struct ucontext* uctx,
    oe_context_t* octx)
{
    octx->rax = uctx->uc_mcontext.rax;
    octx->rbx = uctx->uc_mcontext.rbx;
    octx->rcx = uctx->uc_mcontext.rcx;
    octx->rdx = uctx->uc_mcontext.rdx;
    octx->rbp = uctx->uc_mcontext.rbp;
    octx->rsp = uctx->uc_mcontext.rsp;
    octx->rdi = uctx->uc_mcontext.rdi;
    octx->rsi = uctx->uc_mcontext.rsi;
    octx->r8 = uctx->uc_mcontext.r8;
    octx->r9 = uctx->uc_mcontext.r9;
    octx->r10 = uctx->uc_mcontext.r10;
    octx->r11 = uctx->uc_mcontext.r11;
    octx->r12 = uctx->uc_mcontext.r12;
    octx->r13 = uctx->uc_mcontext.r13;
    octx->r14 = uctx->uc_mcontext.r14;
    octx->r15 = uctx->uc_mcontext.r15;
    octx->rip = uctx->uc_mcontext.rip;
}

static uint64_t sgxlkl_enclave_signal_handler(
    oe_exception_record_t* exception_record)
{
    int ret = -1;
    siginfo_t info;
    struct ucontext uctx;
    struct oe_hw_exception_map trap_info;
    oe_context_t* oe_ctx = exception_record->context;
    uint16_t *instr_addr = ((uint16_t*)exception_record->context->rip);
    uint16_t opcode = instr_addr ? *instr_addr : 0;

    /* Emulate illegal instructions in SGX hardware mode */
    if (exception_record->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        SGXLKL_TRACE_SIGNAL(
            "Exception SIGILL (illegal instruction) received (code=%d "
            "address=0x%lx opcode=0x%x)\n",
            exception_record->code,
            exception_record->address,
            opcode);

        _sgxlkl_illegal_instr_hook(opcode, exception_record->context);
        return OE_EXCEPTION_CONTINUE_EXECUTION;
    }

    memset(&trap_info, 0, sizeof(trap_info));
    ret = get_trap_details(exception_record->code, &trap_info);
    if (ret != -1 && lkl_is_running())
    {
        SGXLKL_TRACE_SIGNAL(
            "Exception %s received (code=%d address=0x%lx opcode=0x%x)\n",
            trap_info.description,
            exception_record->code,
            exception_record->address,
            opcode);

        memset(&uctx, 0, sizeof(uctx));
        serialize_ucontext(oe_ctx, &uctx);

        info.si_errno = 0;
        info.si_code = exception_record->code;
        info.si_addr = (void*)exception_record->address;
        info.si_signo = trap_info.signo;

        lkl_do_trap(trap_info.trapnr, trap_info.signo, NULL, &uctx, 0, &info);
        deserialize_ucontext(&uctx, oe_ctx);
    }
    else
    {
        sgxlkl_warn(
            "Unhandled exception %s received (code=%i addr=0x%lx opcode=0x%x "
            "lkl_is_running()=%i ret=%i)\n",
            trap_info.description,
            exception_record->code,
            (void*)exception_record->address,
            opcode,
            lkl_is_running(),
            ret);
    }

    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

static void _sgxlkl_illegal_instr_hook(uint16_t opcode, oe_context_t* context)
{
    uint32_t rax, rbx, rcx, rdx;
    switch (opcode)
    {
        case OE_CPUID_OPCODE:
            rax = 0xaa, rbx = 0xbb, rcx = 0xcc, rdx = 0xdd;
            if (context->rax != 0xff)
            {
                /* Call into host to execute the CPUID instruction. */
                sgxlkl_host_hw_cpuid(
                    (uint32_t)context->rax, /* leaf */
                    (uint32_t)context->rcx, /* subleaf */
                    &rax,
                    &rbx,
                    &rcx,
                    &rdx);
            }
            context->rax = rax;
            context->rbx = rbx;
            context->rcx = rcx;
            context->rdx = rdx;
            break;
        case RDTSC_OPCODE:
            rax = 0, rdx = 0;
            /* Call into host to execute the RDTSC instruction */
            sgxlkl_host_hw_rdtsc(&rax, &rdx);
            context->rax = rax;
            context->rdx = rdx;
            break;
        default:
            sgxlkl_fail(
                "Encountered an illegal instruction inside enclave "
                "(opcode=0x%x)\n",
                opcode);
    }

    /* Skip over the illegal instruction. */
    context->rip += 2;
}

void _register_enclave_signal_handlers(int mode)
{
    oe_result_t result;

    SGXLKL_VERBOSE("Registering OE exception handler...\n");

    if (mode == SW_DEBUG_MODE)
    {
        sgxlkl_host_sw_register_signal_handler(
            (void*)sgxlkl_enclave_signal_handler);
    }
    else
    {
        result = oe_add_vectored_exception_handler(
            true, sgxlkl_enclave_signal_handler);
        if (result != OE_OK)
            sgxlkl_fail("OE exception handler registration failed.\n");
    }
}
