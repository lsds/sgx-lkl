#include "lkl/asm/host_ops.h"
#include "lkl/setup.h"

#include <openenclave/internal/globals.h>
#include "openenclave/corelibc/oemalloc.h"
#include "openenclave/corelibc/oestring.h"

#include "enclave/enclave_mem.h"
#include "enclave/enclave_oe.h"
#include "enclave/enclave_util.h"
#include "enclave/lthread.h"
#include "enclave/wireguard.h"
#include "enclave/wireguard_util.h"
#include "shared/env.h"

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

        if (strcmp(cfg_disk->destination, "/") == 0)
            sgxlkl_fail("Error: root disk should not be in 'mounts'.\n");

        bool found = false;
        for (int j = 0; j < shm->num_virtio_blk_dev && !found; j++)
        {
            if (strcmp(cfg_disk->destination, shm->virtio_blk_dev_names[j]) ==
                0)
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

static int startmain(void* args)
{
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

    init_wireguard();
    find_and_mount_disks();

    /* Launch stage 3 dynamic linker, passing in top of stack to overwrite.
     * The dynamic linker will then load the application proper; here goes! */
    __dls3(&sgxlkl_enclave_state.elf64_stack, __builtin_frame_address(0));
}

int __libc_init_enclave(int argc, char** argv)
{
    struct lthread* lt;
    char** envp = argv + argc + 1;

    /* Upper heap memory area is allotted to OE and rest is used by SGXLKL */
    const size_t oe_allotted_heapsize =
        sgxlkl_enclave->oe_heap_pagecount * PAGESIZE;
    const void* sgxlkl_heap_base =
        (void*)((unsigned char*)__oe_get_heap_base() + oe_allotted_heapsize);

    if (oe_allotted_heapsize >= __oe_get_heap_size())
        sgxlkl_fail("Not enough heap memory for OpenEnclave heap\n");

    const size_t sgxlkl_heap_size =
        (__oe_get_heap_size() - oe_allotted_heapsize);

    SGXLKL_VERBOSE("calling enclave_mman_init()\n");
    enclave_mman_init(
        sgxlkl_heap_base,
        sgxlkl_heap_size / PAGESIZE,
        sgxlkl_enclave->mmap_files);

    libc.user_tls_enabled =
        sgxlkl_in_sw_debug_mode() ? 1 : sgxlkl_enclave->fsgsbase;

    init_sysconf(sgxlkl_enclave->ethreads, sgxlkl_enclave->ethreads);

    struct timespec tmp[8] = {0};
    for (size_t i = 0; i < 8; i++)
    {
        tmp[i].tv_sec = hex_to_int(sgxlkl_enclave->clock_res[i].resolution, 8);
        tmp[i].tv_nsec =
            hex_to_int(sgxlkl_enclave->clock_res[i].resolution + 8, 8);
    }
    init_clock_res(tmp);

    size_t max_lthreads =
        sgxlkl_enclave->max_user_threads * sizeof(*__scheduler_queue.buffer);
    max_lthreads = next_power_of_2(max_lthreads);

    newmpmcq(&__scheduler_queue, max_lthreads, 0);

    __init_libc(envp, argv[0]);
    __init_tls();

    size_t futex_wake_spins = DEFAULT_FUTEX_WAKE_SPINS;
    size_t espins = sgxlkl_enclave->espins;
    size_t esleep = sgxlkl_enclave->esleep;
    lthread_sched_global_init(espins, esleep, futex_wake_spins);

    SGXLKL_VERBOSE("calling _lthread_sched_init()\n");
    _lthread_sched_init(sgxlkl_enclave->stacksize);

    if (lthread_create(&lt, NULL, startmain, NULL) != 0)
    {
        sgxlkl_fail("Failed to create lthread for startmain()\n");
    }

    lthread_run();

    return sgxlkl_enclave_state.exit_status;
}
