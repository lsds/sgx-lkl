#include <openenclave/bits/eeid.h>
#include <openenclave/internal/globals.h>
#include "openenclave/corelibc/oestring.h"

#include "enclave/enclave_oe.h"
#include "enclave/enclave_signal.h"
#include "enclave/enclave_util.h"
#include "shared/env.h"
#include "shared/read_enclave_config.h"

sgxlkl_enclave_config_t* sgxlkl_enclave = NULL;
sgxlkl_enclave_state_t sgxlkl_enclave_state = {0};

bool sgxlkl_in_sw_debug_mode()
{
    return sgxlkl_enclave_state.config->mode == SW_DEBUG_MODE;
}

static void prepare_elf_stack()
{
    sgxlkl_enclave_config_t* config = sgxlkl_enclave_state.config;
    sgxlkl_app_config_t* app_cfg = &config->app_config;

    // import host envp
    if (sgxlkl_enclave_state.shared_memory.envp &&
        app_cfg->host_import_envc > 0)
    {
        app_cfg->envp = realloc(
            app_cfg->envp,
            sizeof(char*) * (app_cfg->envc + app_cfg->host_import_envc + 1));
        if (!app_cfg->envp)
            sgxlkl_fail("out of memory\n");

        for (size_t i = 0; i < app_cfg->host_import_envc; i++)
        {
            const char* name = app_cfg->host_import_envp[i];
            for (char* const* p = sgxlkl_enclave_state.shared_memory.envp;
                 p && *p != NULL;
                 p++)
            {
                size_t n = strlen(name);
                if (strncmp(name, *p, n) == 0 && (*p)[n] == '=')
                {
                    const char* str = *p;
                    size_t len = strlen(str);
                    char* cpy = malloc(len + 1);
                    memcpy(cpy, str, len + 1);
                    app_cfg->envp[app_cfg->envc++] = cpy;
                    app_cfg->envp[app_cfg->envc] = NULL;
                }
            }
        }
    }

    int have_run = app_cfg->run != NULL;
    size_t total_size = 0;
    size_t total_count = 1;
    if (have_run)
    {
        total_size += strlen(app_cfg->run) + 1;
        total_count++;
    }
    for (size_t i = 0; i < app_cfg->argc; i++)
        total_size += strlen(app_cfg->argv[i]) + 1;
    total_count += app_cfg->argc + 1;
    for (size_t i = 0; i < app_cfg->envc; i++)
    {
        total_size += strlen(app_cfg->envp[i]) + 1;
        total_count += app_cfg->envc + 1;
    }
    total_count += 1; // auxv terminator
    total_count += 1; // platform-independent stuff terminator

    char* buf = calloc(total_size, sizeof(char));
    char** out = calloc(total_count, sizeof(char*));

    size_t j = 0;
    char* buf_ptr = buf;

#define ADD_STRING(S)               \
    {                               \
        size_t len = strlen(S) + 1; \
        memcpy(buf_ptr, (S), len);  \
        out[j++] = buf_ptr;         \
        buf_ptr += len;             \
        free((void*)S);             \
        S = NULL;                   \
    }

    elf64_stack_t* stack = &sgxlkl_enclave_state.elf64_stack;

    // argv
    stack->argv = out;
    if (have_run)
    {
        ADD_STRING(app_cfg->run);
    }
    for (size_t i = 0; i < app_cfg->argc; i++)
        ADD_STRING(app_cfg->argv[i]);
    stack->argc = j;
    out[j++] = NULL;

    // envp
    stack->envp = out + j;
    for (size_t i = 0; i < app_cfg->envc; i++)
        ADD_STRING(app_cfg->envp[i]);
    out[j++] = NULL;

    // auxv
    stack->auxv = (Elf64_auxv_t**)(out + j);
    for (size_t i = 0; i < app_cfg->auxc; i++)
    {
        out[j++] = (char*)app_cfg->auxv[i]->a_type;
        out[j++] = (char*)app_cfg->auxv[i]->a_un.a_val;
    }
    out[j++] = NULL;

    // TODO: platform independent things?
    out[j++] = NULL;

    // CHECK: should the memory holding the strings also be on the stack?
}

// We need to have a separate function here
int __sgx_init_enclave()
{
    sgxlkl_enclave_config_t* config = sgxlkl_enclave_state.config;
    _register_enclave_signal_handlers(config->mode);

    prepare_elf_stack();

    return __libc_init_enclave(
        sgxlkl_enclave_state.elf64_stack.argc,
        sgxlkl_enclave_state.elf64_stack.argv);
}

#ifdef DEBUG
static void _size_uint64_to_str(uint64_t size, char* buf, uint64_t len)
{
    int i = 0;
    double bytes = size;
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    const int unit_len = sizeof(units) / sizeof(units[0]);

    while (bytes > 1024.0 && i < unit_len)
    {
        bytes /= 1024.0;
        i++;
    }

    /*
     * The following works around oe_snprintf's lack of support for the
     * "%f" format specifier.
     */
    unsigned int whole_part = (unsigned int)bytes;
    double fraction_double = bytes - whole_part;
    unsigned int fraction_part = (unsigned int)(fraction_double * 1000);

    oe_snprintf(buf, len, "%i.%i %s", whole_part, fraction_part, units[i]);
}

static void _sgxlkl_enclave_show_attribute(const void* sgxlkl_enclave_base)
{
    char enclave_size_str[16];

    size_t sgxlkl_enclave_size = __oe_get_enclave_size();
    size_t sgxlkl_enclave_heap_size = __oe_get_heap_size();
    const void* sgxlkl_enclave_heap_base = __oe_get_heap_base();
    const void* sgxlkl_enclave_heap_end = __oe_get_heap_end();

    _size_uint64_to_str(
        sgxlkl_enclave_size, enclave_size_str, sizeof(enclave_size_str));

    SGXLKL_VERBOSE(
        "enclave base=0x%p size=%s\n", sgxlkl_enclave_base, enclave_size_str);

    _size_uint64_to_str(
        sgxlkl_enclave_heap_size, enclave_size_str, sizeof(enclave_size_str));

    SGXLKL_VERBOSE(
        "enclave heap base=0x%p size=%s end=0x%p\n",
        sgxlkl_enclave_heap_base,
        enclave_size_str,
        sgxlkl_enclave_heap_end);
}
#endif

void sgxlkl_ethread_init(void)
{
    void* tls_page;
    __asm__ __volatile__("mov %%fs:0,%0" : "=r"(tls_page));

    struct sched_tcb_base* sched_tcb = (struct sched_tcb_base*)tls_page;
    sched_tcb->self = (void*)tls_page;

    size_t tls_offset = SCHEDCTX_OFFSET;
    sched_tcb->schedctx = (struct schedctx*)((char*)tls_page + tls_offset);

    /* Wait until libc has been initialized */
    while (sgxlkl_enclave_state.libc_state != libc_initialized)
    {
        a_spin();
    }

    /* Initialization completed, now run the scheduler */
    __init_tls();
    _lthread_sched_init(sgxlkl_enclave_state.config->stacksize);
    lthread_run();

    return;
}

static int _read_eeid_config(const sgxlkl_shared_memory_t* shm)
{
    const oe_eeid_t* eeid = (oe_eeid_t*)__oe_get_eeid();
    const char* config_json = (const char*)eeid->data;
    sgxlkl_enclave_state.libc_state = libc_not_started;

    if (sgxlkl_read_enclave_config(config_json, &sgxlkl_enclave_state.config))
        return 1;

    // Copy shared memory. Deep copy so the host can't change it?
    memcpy(
        &sgxlkl_enclave_state.shared_memory,
        shm,
        sizeof(sgxlkl_shared_memory_t));

    // This will be removed once shared memory and config have been
    // separated fully.
    sgxlkl_enclave = sgxlkl_enclave_state.config;

    return 0;
}

int sgxlkl_enclave_init(const sgxlkl_shared_memory_t* shared_memory)
{
    SGXLKL_ASSERT(shared_memory);

    memset(&sgxlkl_enclave_state, 0, sizeof(sgxlkl_enclave_state));
    sgxlkl_enclave_state.libc_state = libc_not_started;

    sgxlkl_verbose = 0;

    if (_read_eeid_config(shared_memory))
        return 1;

    // Initialise verbosity setting, so SGXLKL_VERBOSE can be used from this
    // point onwards
    sgxlkl_verbose = sgxlkl_enclave_state.config->verbose;

    SGXLKL_VERBOSE("enter\n");

    void* tls_page;
    __asm__ __volatile__("mov %%fs:0,%0" : "=r"(tls_page));

    struct sched_tcb_base* sched_tcb = (struct sched_tcb_base*)tls_page;
    sched_tcb->self = (void*)tls_page;

    size_t tls_offset = SCHEDCTX_OFFSET;
    sched_tcb->schedctx = (struct schedctx*)((char*)tls_page + tls_offset);

    const void* sgxlkl_enclave_base = __oe_get_enclave_base();

#ifdef DEBUG
    _sgxlkl_enclave_show_attribute(sgxlkl_enclave_base);
#endif

    /* Indicate ongoing libc initialisation */
    sgxlkl_enclave_state.libc_state = libc_initializing;

    SGXLKL_VERBOSE("calling _dlstart_c()\n");
    _dlstart_c((size_t)sgxlkl_enclave_base);

    return __sgx_init_enclave();
}
