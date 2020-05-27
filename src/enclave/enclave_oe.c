#include <string.h>

#include "pthread_impl.h"

#include <openenclave/internal/globals.h>

#include "enclave/enclave_oe.h"
#include "enclave/enclave_signal.h"
#include "lkl/lkl_util.h"
#include "enclave/sgxlkl_config.h"
#include "shared/env.h"

extern int sgxlkl_verbose;

extern _Atomic(enum sgxlkl_libc_state) __libc_state;

sgxlkl_config_t* sgxlkl_enclave;

// We need to have a separate function here
int __sgx_init_enclave()
{
    _register_enclave_signal_handlers(sgxlkl_enclave->mode);

    return __libc_init_enclave(sgxlkl_enclave->argc, sgxlkl_enclave->argv);
}

void sgxlkl_enclave_show_attribute(const void* sgxlkl_enclave_base)
{
    char enclave_size_str[10];

    size_t sgxlkl_enclave_size = __oe_get_enclave_size();
    size_t sgxlkl_enclave_heap_size = __oe_get_heap_size();
    const void* sgxlkl_enclave_heap_base = __oe_get_heap_base();
    const void* sgxlkl_enclave_heap_end = __oe_get_heap_end();

    size_uint64_to_str(sgxlkl_enclave_size, enclave_size_str, 10);

    SGXLKL_VERBOSE(
        "enclave base=0x%p size=%s\n", sgxlkl_enclave_base, enclave_size_str);

    memset(enclave_size_str, 0, sizeof(enclave_size_str));
    size_uint64_to_str(sgxlkl_enclave_heap_size, enclave_size_str, 10);
    SGXLKL_VERBOSE(
        "enclave heap base=0x%p size=%s end=0x%p\n",
        sgxlkl_enclave_heap_base,
        enclave_size_str,
        sgxlkl_enclave_heap_end);
    return;
}

void sgxlkl_ethread_init(void)
{
    void* tls_page;
    __asm__ __volatile__("mov %%fs:0,%0" : "=r"(tls_page));

    struct sched_tcb_base* sched_tcb = (struct sched_tcb_base*)tls_page;
    sched_tcb->self = (void*)tls_page;

    size_t tls_offset = SCHEDCTX_OFFSET;
    sched_tcb->schedctx = (struct schedctx*)((char*)tls_page + tls_offset);

    /* Wait until libc has been initialized */
    while (__libc_state != libc_initialized)
    {
        a_spin();
    }

    /* Initialization completed, now run the scheduler */
    __init_tls();
    _lthread_sched_init(sgxlkl_enclave->stacksize);
    lthread_run();

    return;
}

int sgxlkl_enclave_init(const sgxlkl_config_t* config_on_host)
{
    SGXLKL_ASSERT(config_on_host);

    // Initialise verbosity setting, so SGXLKL_VERBOSE can be used from this
    // point onwards
    sgxlkl_verbose = config_on_host->verbose;

    SGXLKL_VERBOSE("enter\n");

    // Make sure all configuration and state is held in enclave memory.
    sgxlkl_copy_config(config_on_host, &sgxlkl_enclave);

    // Sanity checks
    SGXLKL_ASSERT(oe_is_within_enclave(&sgxlkl_enclave->mode, sizeof(int)));
    if (sgxlkl_enclave->num_disks > 0)
    {
        SGXLKL_ASSERT(oe_is_within_enclave(
            &sgxlkl_enclave->disks[0], sizeof(enclave_disk_config_t)));
    }

    void* tls_page;
    __asm__ __volatile__("mov %%fs:0,%0" : "=r"(tls_page));

    struct sched_tcb_base* sched_tcb = (struct sched_tcb_base*)tls_page;
    sched_tcb->self = (void*)tls_page;

    size_t tls_offset = SCHEDCTX_OFFSET;
    sched_tcb->schedctx = (struct schedctx*)((char*)tls_page + tls_offset);

    const void* sgxlkl_enclave_base = __oe_get_enclave_base();
    sgxlkl_enclave_show_attribute(sgxlkl_enclave_base);

    /* Indicate ongoing libc initialisation */
    __libc_state = libc_initializing;

    SGXLKL_VERBOSE("calling _dlstart_c()\n");
    _dlstart_c((size_t)sgxlkl_enclave_base);

    return __sgx_init_enclave();
}
