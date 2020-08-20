#include "lkl/asm/host_ops.h"
#include "lkl/setup.h"

#include <openenclave/internal/globals.h>
#include "openenclave/corelibc/oemalloc.h"
#include "openenclave/corelibc/oestring.h"

#include "enclave/enclave_mem.h"
#include "enclave/enclave_oe.h"
#include "enclave/enclave_util.h"
#include "enclave/lthread.h"
#include "enclave/lthread_int.h"
#include "enclave/wireguard.h"
#include "enclave/wireguard_util.h"
#include "shared/env.h"

#include "../../user/userargs.h"

extern struct mpmcq __scheduler_queue;

_Noreturn void __dls3(elf64_stack_t* conf, void* tos);
extern void init_sysconf(long nproc_conf, long nproc_onln);

static void find_and_mount_disks()
{
    const sgxlkl_enclave_config_t* cfg = sgxlkl_enclave_state.config;
    size_t n = cfg->num_mounts + 1;

    sgxlkl_enclave_state_t* estate = &sgxlkl_enclave_state;
    const sgxlkl_shared_memory_t* shm = &estate->shared_memory;

    estate->disk_state = oe_calloc(n, sizeof(sgxlkl_enclave_disk_state_t));
    estate->num_disk_state = n;

    // root disk index
    estate->disk_state[0].host_disk_index = 0;

    for (int i = 0; i < cfg->num_mounts; i++)
    {
        const sgxlkl_enclave_mount_config_t* cfg_disk = &cfg->mounts[i];

        if (oe_strcmp(cfg_disk->destination, "/") == 0)
            sgxlkl_fail("root disk should not be in 'mounts'.\n");

        bool found = false;
        for (int j = 0; j < shm->num_virtio_blk_dev && !found; j++)
        {
            if (oe_strcmp(
                    cfg_disk->destination, shm->virtio_blk_dev_names[j]) == 0)
            {
                estate->disk_state[i + 1].host_disk_index = j;
                found = true;
            }
        }
        if (!found)
            sgxlkl_fail(
                "Disk image for mount point '%s' has not been provided by "
                "host.\n",
                cfg_disk->destination);
    }

    lkl_mount_disks(&cfg->root, cfg->mounts, cfg->num_mounts, cfg->cwd);
}

static void init_wireguard()
{
    const sgxlkl_enclave_config_t* cfg = sgxlkl_enclave_state.config;

    /* Get WG public key */
    wg_device* wg_dev;
    if (wg_get_device(&wg_dev, "wg0"))
        sgxlkl_fail("Failed to locate Wireguard interface 'wg0'.\n");

    if (cfg->verbose)
    {
        wg_key_b64_string key;
        wg_key_to_base64(key, wg_dev->public_key);
        sgxlkl_info("wg0 has public key %s\n", key);
    }

    /* Add peers */
    if (wg_dev)
    {
        wgu_add_peers(wg_dev, cfg->wg.peers, cfg->wg.num_peers, 1);
    }
    else if (cfg->wg.num_peers)
    {
        sgxlkl_warn("Failed to add wireguard peers: No device 'wg0' found.\n");
    }
    if (cfg->wg.num_peers && cfg->verbose)
        wgu_list_devices();
}

static int _sgxlkl_host_syscall_mprotect(
    int* retval, void* addr, size_t len, int prot)
{
    return (int)sgxlkl_host_syscall_mprotect(retval, addr, len, prot);
}

void _barrier(void)
{
    a_barrier();
}

static long _lkl_syscall_wrapper(long no, long* params)
{
    //sgxlkl_warn("syscall begin: no=%u\n", no);
    long ret = lkl_syscall(no, params);
    //sgxlkl_warn("syscall end: ret=%u\n", ret);
    return ret;
}

static void _enter_user_space(
    int argc,
    char** argv,
    void* stack,
    size_t num_ethreads,
    struct timespec clock_res[4])
{
    extern void* __oe_get_isolated_image_entry_point(void);
    extern const void* __oe_get_isolated_image_base();
    typedef int (*sgxlkl_user_enter_proc_t)(void* userargs);
    sgxlkl_user_enter_proc_t proc = __oe_get_isolated_image_entry_point();
    static sgxlkl_userargs_t _userargs =
    {
        /* ATTN:MEB: eliminate all of these bypasses except lkl_syscall */
        _lkl_syscall_wrapper,
        sgxlkl_warn,
        sgxlkl_error,
        sgxlkl_fail,
        lthread_current,
        enclave_mmap,
        _sgxlkl_host_syscall_mprotect,
    };

    if (!proc)
        sgxlkl_fail("failed to obtain user space entry point");

    _userargs.argc = argc;
    _userargs.argv = argv;
    _userargs.stack = stack;
    _userargs.elf64_hdr = (const void*)__oe_get_isolated_image_base();
    _userargs.num_ethreads = num_ethreads;
    _userargs.sw_debug_mode = sgxlkl_in_sw_debug_mode();
    memcpy(_userargs.clock_res, clock_res, sizeof(_userargs.clock_res));

    (*proc)(&_userargs);
}

typedef struct startmain_args
{
    int argc;
    char** argv;
    struct timespec clock_res[8];
}
startmain_args_t;

static int startmain(void* args_)
{
    startmain_args_t* args = args_;

    __init_libc(sgxlkl_enclave_state.elf64_stack.envp,
        sgxlkl_enclave_state.elf64_stack.argv[0]);
    __libc_start_init();
    a_barrier();

    /* Indicate that libc initialization has finished */
    sgxlkl_enclave_state.libc_state = libc_initialized;

    /* Setup LKL (hd, net, memory) and start kernel */

    /* SGX-LKL lthreads inherit names from their parent. Set this to "kernel"
     * temporarily to be able to identify LKL kernel threads */
    lthread_set_funcname(lthread_self(), "kernel");
    lkl_start_init();
    lthread_set_funcname(lthread_self(), "sgx-lkl-init");

    /* Set locale for usersapce components using it */
    pthread_t self = __pthread_self();
    self->locale = &libc.global_locale;

    init_wireguard();
    find_and_mount_disks();

/* Change to 0 to run application within the kernel image */
#if 1
    /* Enter the isolated image */
    _enter_user_space(
        args->argc,
        args->argv,
        &sgxlkl_enclave_state.elf64_stack,
        sgxlkl_enclave_state.config->ethreads,
        args->clock_res);
#else
    /* Launch stage 3 dynamic linker, passing in top of stack to overwrite.
     * The dynamic linker will then load the application proper; here goes! */
    __dls3(&sgxlkl_enclave_state.elf64_stack, __builtin_frame_address(0));
    (void)_enter_user_space;
    (void)args;
#endif
    return 0;
}

int __libc_init_enclave(int argc, char** argv)
{
    struct lthread* lt;
    const sgxlkl_enclave_config_t* cfg = sgxlkl_enclave_state.config;

    /* Upper heap memory area is allotted to OE and rest is used by SGXLKL */
    const size_t oe_allotted_heapsize = cfg->oe_heap_pagecount * PAGESIZE;
    const void* sgxlkl_heap_base =
        (void*)((unsigned char*)__oe_get_heap_base() + oe_allotted_heapsize);

    if (oe_allotted_heapsize >= __oe_get_heap_size())
        sgxlkl_fail("Not enough heap memory for Open Enclave heap\n");

    const size_t sgxlkl_heap_size =
        (__oe_get_heap_size() - oe_allotted_heapsize);

    SGXLKL_VERBOSE("calling enclave_mman_init()\n");
    enclave_mman_init(
        sgxlkl_heap_base, sgxlkl_heap_size / PAGESIZE, cfg->mmap_files);

    libc.user_tls_enabled = sgxlkl_in_sw_debug_mode() ? 1 : cfg->fsgsbase;

    init_sysconf(cfg->ethreads, cfg->ethreads);

    struct timespec tmp[8] = {0};
    for (size_t i = 0; i < 8; i++)
    {
        tmp[i].tv_sec = hex_to_int(cfg->clock_res[i].resolution, 8);
        tmp[i].tv_nsec = hex_to_int(cfg->clock_res[i].resolution + 8, 8);
    }
    init_clock_res(tmp);

    size_t max_lthreads =
        cfg->max_user_threads * sizeof(*__scheduler_queue.buffer);
    max_lthreads = next_power_of_2(max_lthreads);

    newmpmcq(&__scheduler_queue, max_lthreads, 0);

    init_ethread_tp();

    size_t espins = cfg->espins;
    size_t esleep = cfg->esleep;
    lthread_sched_global_init(espins, esleep);

    SGXLKL_VERBOSE("calling _lthread_sched_init()\n");
    _lthread_sched_init(cfg->stacksize);

    /* Run startmain() in a new lthread */
    {
        static startmain_args_t args;
        args.argc = argc;
        args.argv = argv;
        memcpy(args.clock_res, tmp, sizeof(args.clock_res));

        if (lthread_create(&lt, NULL, startmain, &args) != 0)
            sgxlkl_fail("Failed to create lthread for startmain()\n");
    }

    lthread_run();
    return sgxlkl_enclave_state.exit_status;
}
