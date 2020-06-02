#include "lkl/asm/host_ops.h"
#include "lkl/setup.h"

#include <openenclave/internal/globals.h>
#include "openenclave/corelibc/oemalloc.h"
#include "openenclave/corelibc/oestring.h"

#include "enclave/enclave_mem.h"
#include "enclave/enclave_oe.h"
#include "enclave/enclave_util.h"
#include "enclave/lthread.h"
#include "enclave/sgxlkl_config.h"
#include "enclave/wireguard.h"
#include "enclave/wireguard_util.h"
#include "shared/env.h"
#include "shared/sgxlkl_app_config.h"

_Atomic(enum sgxlkl_libc_state) __libc_state = libc_not_started;

_Atomic(int)
    sgxlkl_exit_status = 0; /* Exit status returned when LKL terminates */

struct lkl_host_operations lkl_host_ops;
struct lkl_host_operations sgxlkl_host_ops;

extern struct mpmcq __scheduler_queue;

_Noreturn void __dls3(sgxlkl_enclave_config_t* conf, void* tos);
extern void init_sysconf(long nproc_conf, long nproc_onln);

int find_and_mount_disks(const sgxlkl_app_config_t* app_config)
{
    if (!app_config)
        sgxlkl_fail("bug: no app config\n");

    size_t num_disks =
        app_config->disks ? app_config->num_disks : sgxlkl_enclave->num_disks;

    if (num_disks == 0)
        sgxlkl_fail("bug: no disks\n");

    sgxlkl_enclave_disk_config_t disks_to_mount[num_disks];

    sgxlkl_enclave_state.disk_state =
        oe_calloc(num_disks, sizeof(sgxlkl_enclave_disk_state_t));
    sgxlkl_enclave_state.num_disk_state = num_disks;

    /* Disk config has been set through app config
     * Merge host-provided disk info (fd, capacity, mmap) */
    if (app_config->disks)
    {
        for (int i = 0; i < num_disks; i++)
        {
            sgxlkl_app_disk_config_t* app_disk = &app_config->disks[i];
            sgxlkl_enclave_disk_config_t* host_disk = NULL;
            for (int j = 0; j < sgxlkl_enclave->num_disks && !host_disk; j++)
            {
                sgxlkl_enclave_disk_config_t* it = &sgxlkl_enclave->disks[j];
                if (strcmp(app_disk->mnt, it->mnt) == 0)
                {
                    host_disk = it;
                    sgxlkl_enclave_state.disk_state[i].host_disk_index = j;
                }
            }
            if (!host_disk)
                sgxlkl_fail(
                    "Disk image for mount point '%s' has not been provided by "
                    "host.\n",
                    app_disk->mnt);
            else
            {
                disks_to_mount[i] = *host_disk;

                if (app_disk->key_len && app_disk->key)
                {
                    host_disk->key = malloc(app_disk->key_len);
                    memcpy(host_disk->key, app_disk->key, app_disk->key_len);
                }
            }
        }
    }
    else
    {
        for (size_t i = 0; i < sgxlkl_enclave->num_disks; i++)
            disks_to_mount[i] = sgxlkl_enclave->disks[i];
    }

    lkl_mount_disks(disks_to_mount, num_disks, app_config->cwd);
}

static void test_attestation()
{
    /* Retrieve remote attestation report to exercise Azure DCAP Client (for
     * testing only) */
    // TODO replace this later on
    if (sgxlkl_enclave->mode == HW_DEBUG_MODE)
    {
        uint8_t* remote_report;
        size_t remote_report_size;
        oe_result_t result = OE_UNEXPECTED;
        result = oe_get_report_v2(
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            NULL,
            0,
            &remote_report,
            &remote_report_size);
        if (OE_OK != result)
            sgxlkl_fail(
                "Failed to retrieve report via oe_get_report_v2: %d.\n",
                result);
        oe_free_report(&remote_report);
    }
}

static int startmain(void* args)
{
    __libc_start_init();
    a_barrier();

    /* Indicate that libc initialization has finished */
    __libc_state = libc_initialized;

    /* Setup LKL (hd, net, memory) and start kernel */

    /* SGX-LKL lthreads inherit names from their parent. Set this to "kernel"
     * temporarily to be able to identify LKL kernel threads */
    lthread_set_funcname(lthread_self(), "kernel");
    lkl_start_init();
    lthread_set_funcname(lthread_self(), "sgx-lkl-init");

    /* Get WG public key */
    wg_device* wg_dev;
    if (wg_get_device(&wg_dev, "wg0"))
        sgxlkl_fail("Failed to locate Wireguard interface 'wg0'.\n");

    if (sgxlkl_enclave->verbose)
    {
        wg_key_b64_string key;
        wg_key_to_base64(key, wg_dev->public_key);
        sgxlkl_info("wg0 has public key %s\n", key);
    }

    if (false)
        test_attestation();

    sgxlkl_app_config_t* app_config = sgxlkl_enclave_state.app_config;
    find_and_mount_disks(app_config);

    // Add Wireguard peers
    if (wg_dev)
    {
        wgu_add_peers(wg_dev, app_config->peers, app_config->num_peers, 1);
    }
    else if (app_config->num_peers)
    {
        sgxlkl_warn("Failed to add wireguard peers: No device 'wg0' found.\n");
    }
    if (app_config->num_peers && sgxlkl_enclave->verbose)
        wgu_list_devices();

    /* Launch stage 3 dynamic linker, passing in top of stack to overwrite.
     * The dynamic linker will then load the application proper; here goes! */
    __dls3(sgxlkl_enclave_state.enclave_config, __builtin_frame_address(0));
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
    const size_t sgxlkl_heap_size =
        (__oe_get_heap_size() - oe_allotted_heapsize);

    SGXLKL_VERBOSE("calling enclave_mman_init()\n");
    enclave_mman_init(
        sgxlkl_heap_base,
        sgxlkl_heap_size / PAGESIZE,
        sgxlkl_enclave->mmap_files);

    libc.vvar_base = sgxlkl_enclave->shared_memory.vvar;
    libc.user_tls_enabled =
        sgxlkl_enclave->mode == SW_DEBUG_MODE ? 1 : sgxlkl_enclave->fsgsbase;

    init_sysconf(
        sgxlkl_enclave->sysconf_nproc_conf, sgxlkl_enclave->sysconf_nproc_onln);

    init_clock_res(sgxlkl_enclave->clock_res);

    size_t max_lthreads =
        sgxlkl_enclave->max_user_threads * sizeof(*__scheduler_queue.buffer);
    max_lthreads = next_power_of_2(max_lthreads);

    newmpmcq(&__scheduler_queue, max_lthreads, 0);

    __init_libc(envp, argv[0]);
    __init_tls();

    size_t futex_wake_spins = sgxlkl_enclave->shared_memory.vvar ? 1 : 500;
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

    return sgxlkl_exit_status;
}
