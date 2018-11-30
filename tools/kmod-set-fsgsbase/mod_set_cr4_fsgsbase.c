#include <linux/init.h>
#include <linux/module.h>
#include <asm/smp.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Imperial College London");
MODULE_DESCRIPTION("Module to set CR4.FSGSBASE control register bit in order to allow enclave code to use WRFSBASE instruction.");

static int val;
module_param(val, int, 0000);
MODULE_PARM_DESC(val, "New value of CR4.FSGSBASE (0 or 1).");

#define SET_RAX_BIT16_0 "and $0xFFFFFFFFFFFEFFFF, %%rax;\n\t"
#define SET_RAX_BIT16_1 " or $(1 << 16), %%rax;\n\t"

#define SETFSGSBASE(val) {                \
    __asm__ __volatile__ (                \
        "mov    %%cr4,      %%rax;\n\t"   \
        "mov    %%rax,      %0;\n\t"      \
        SET_RAX_BIT16_##val               \
        "mov    %%rax,      %%cr4;\n\t"   \
        "wbinvd\n\t"                      \
        "mov    %%cr4,      %%rax;\n\t"   \
        "mov    %%rax,      %1;\n\t"      \
      : "=g" (cr4before), "=g" (cr4after) \
      : /* no input */                    \
      : "%rax"                            \
    );}


void set_cr4_fsgsbase(void *_) {
    u64 cr4before, cr4after;

    val = val >= 1 ? 1 : 0;
    if (val) {
        SETFSGSBASE(1);
    } else {
        SETFSGSBASE(0);
    };
    printk(KERN_ALERT "SGX-LKL: Successfully set CR4.FSGSBASE to %d on CPU #%d, CR4 before: 0x%8.8llx, after: 0x%8.8llx.\n", val, smp_processor_id(), cr4before, cr4after);
}

int init_module(void) {
#ifdef __x86_64__
    printk(KERN_ALERT "SGX-LKL: Setting CR4.FSGSBASE to %d...\n", val);
    set_cr4_fsgsbase(NULL);
    smp_call_function(&set_cr4_fsgsbase, NULL, 0);
#else
    printk(KERN_ALERT "SGX-LKL: Cannot set CR4.FSGSBASE. Platform is not x86-64.\n");
#endif /* __x86_64__ */

    return 0;
}
void cleanup_module(void) {
    // Nothing to do.
}
