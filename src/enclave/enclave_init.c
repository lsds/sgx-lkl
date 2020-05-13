#include <libc.h>
#include <string.h>
#include <time.h>

#include "pthread.h"
#include "pthread_impl.h"

#include "lkl/asm/host_ops.h"
#include "lkl/setup.h"

#include <openenclave/internal/globals.h>

#include "enclave/enclave_mem.h"
#include "enclave/enclave_util.h"
#include "enclave/lthread.h"
#include "enclave/sgxlkl_app_config.h"
#include "enclave/sgxlkl_config.h"
#include "enclave/wireguard.h"
#include "enclave/wireguard_util.h"
#include "shared/env.h"

#include "openenclave/corelibc/oemalloc.h"
#include "openenclave/corelibc/oestring.h"

_Atomic(enum sgxlkl_libc_state) __libc_state = libc_not_started;

int sgxlkl_verbose = 1;

_Atomic(int)
    sgxlkl_exit_status = 0; /* Exit status returned when LKL terminates */

struct lkl_host_operations lkl_host_ops;
struct lkl_host_operations sgxlkl_host_ops;

extern struct mpmcq __scheduler_queue;

_Noreturn void __dls3(sgxlkl_app_config_t* conf, void* tos);
extern void init_sysconf(long nproc_conf, long nproc_onln);

/* Copy the application setting/conf to enclave memory */
static void __sgxlkl_enclave_copy_app_config(
    sgxlkl_app_config_t* app_config,
    const sgxlkl_config_t* sgxlkl_config)
{
    int i = 0, j = 0;
    char** envp = NULL;

    sgxlkl_info("SEAN A ==============> 1\n");
    app_config->argc = sgxlkl_config->argc;
    app_config->argv = oe_malloc((app_config->argc + 1) * sizeof(char*));
    if (app_config->argv == NULL)
        sgxlkl_fail("Unable to allocate memory for appconfig\n");

    sgxlkl_info("SEAN A ==============> 2\n");

    for (i = 0; i < app_config->argc; i++) {
        app_config->argv[i] = oe_strdup(sgxlkl_config->argv[i]);
        if (app_config->argv[i] == NULL)
            sgxlkl_fail("Unable to allocate memory for appconfig\n");
    }
    app_config->argv[i] = NULL;

    sgxlkl_info("SEAN A ==============> 3\n");

    envp = sgxlkl_config->argv + sgxlkl_config->argc + 1;
    for (; envp[j++] != NULL;)
      ;


    sgxlkl_info("SEAN A ==============> 4\n");

    app_config->envp = oe_malloc((j + 1) * sizeof(char*));
    if (app_config->envp == NULL)
        sgxlkl_fail("Unable to allocate memory for appconfig\n");
    for (j = 0; envp[j] != NULL; j++) {
        app_config->envp[j] = oe_strdup(envp[j]);
        if (app_config->envp[j] == NULL)
            sgxlkl_fail("Unable to allocate memory for appconfig\n");
    }
    app_config->envp[j] = NULL;

    sgxlkl_info("SEAN A ==============> 5\n");

    app_config->cwd = oe_strdup(sgxlkl_config->cwd);
    if (app_config->cwd == NULL)
        sgxlkl_fail("Unable to allocate memory for appconfig\n");

    sgxlkl_info("SEAN A ==============> 6\n");

    return;
}

static void enclave_get_app_config(sgxlkl_app_config_t* app_config)
{
    sgxlkl_info("SEAN =====> 1\n");


    /* Get the application configuration & HDD param from remote server */
    if (sgxlkl_enclave->mode == HW_RELEASE_MODE)
    {
            sgxlkl_info("SEAN =====> 2\n");

        sgxlkl_fail("Remote configuration not supported.\n");
    }
    else
    {
            sgxlkl_info("SEAN =====> 3\n");

        if (sgxlkl_enclave->app_config_str)
        {
                sgxlkl_info("SEAN =====> 4\n");

            char* err_desc;
            int ret = parse_sgxlkl_app_config_from_str(
                sgxlkl_enclave->app_config_str, app_config, &err_desc);
            if (ret)
                sgxlkl_fail(
                    "Failed to parse application configuration: %s\n",
                    err_desc);

            /* Validate the app config after parsing */
            ret = validate_sgxlkl_app_config(app_config);
            if (ret)
                sgxlkl_fail("Application configuration is not proper\n");
        }
        else
        {
                sgxlkl_info("SEAN =====> 5\n");

            __sgxlkl_enclave_copy_app_config(app_config, sgxlkl_enclave);
        }
    }

    sgxlkl_info("SEAN =====> 6\n");

    return;
}

static int startmain(void* args)
{
    sgxlkl_app_config_t app_config = {0};

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

    if (sgxlkl_verbose)
    {
        wg_key_b64_string key;
        wg_key_to_base64(key, wg_dev->public_key);
        sgxlkl_info("wg0 has public key %s\n", key);
    }

    /* Get the application configuration & disk param from remote server */
    enclave_get_app_config(&app_config);

    sgxlkl_info("SEAN B ==============> 1\n");

    /* Disk config has been set through app config
     * Merge host-provided disk info (fd, capacity, mmap) */
    if (app_config.disks)
    {
            sgxlkl_info("SEAN B ==============> 1.1\n");

        for (int i = 0; i < app_config.num_disks; i++)
        {
            enclave_disk_config_t* disk = &app_config.disks[i];
            // Initialize fd with -1 to make sure we don't try to mount disks
            // for which no fd has been provided by the host.
            disk->fd = -1;
            for (int j = 0; j < sgxlkl_enclave->num_disks; j++)
            {
                enclave_disk_config_t* disk_untrusted =
                    &sgxlkl_enclave->disks[j];
                if (!strcmp(disk->mnt, disk_untrusted->mnt))
                {
                    disk->fd = disk_untrusted->fd;
                    disk->capacity = disk_untrusted->capacity;
                    disk->mmap = disk_untrusted->mmap;
                    /* restore the virtio memory allocated by loader */
                    disk->virtio_blk_dev_mem =
                        sgxlkl_enclave->disks[j].virtio_blk_dev_mem;
                    break;
                }
            }
            // TODO Propagate error (message) back to remote user.
            if (disk->fd == -1)
                sgxlkl_fail(
                    "Disk image for mount point '%s' has not been provided by "
                    "host.\n",
                    disk->mnt);
        }
    }
    else
    {
        app_config.num_disks = sgxlkl_enclave->num_disks;
        app_config.disks = sgxlkl_enclave->disks;
    }

    sgxlkl_info("SEAN B ==============> 2\n");

    // Mount disks
    lkl_mount_disks(app_config.disks, app_config.num_disks, app_config.cwd);

    sgxlkl_info("SEAN B ==============> 3\n");

    // Add Wireguard peers
    if (wg_dev)
    {
        wgu_add_peers(wg_dev, app_config.peers, app_config.num_peers, 1);
    }
    else if (app_config.num_peers)
    {
        sgxlkl_warn("Failed to add wireguard peers: No device 'wg0' found.\n");
    }
    if (app_config.num_peers && sgxlkl_verbose)
        wgu_list_devices();

    sgxlkl_info("SEAN B ==============> 4\n");

    /* Launch stage 3 dynamic linker, passing in top of stack to overwrite.
     * The dynamic linker will then load the application proper; here goes! */
    __dls3(&app_config, __builtin_frame_address(0));

    sgxlkl_info("SEAN B ================> 5\n");
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

    enclave_mman_init(
        sgxlkl_heap_base,
        sgxlkl_heap_size / PAGESIZE,
        sgxlkl_enclave->mmap_files);

    libc.vvar_base = sgxlkl_enclave->shared_memory.vvar;
    //libc.user_tls_enabled = sgxlkl_enclave->fsgsbase;
    //libc.user_tls_enabled =
    //    sgxlkl_enclave->mode == SW_DEBUG_MODE ? 1 : sgxlkl_enclave->fsgsbase;
    libc.user_tls_enabled = 1;


    init_sysconf(
        sgxlkl_enclave->sysconf_nproc_conf, sgxlkl_enclave->sysconf_nproc_onln);
    init_clock_res(sgxlkl_enclave->clock_res);

    size_t max_lthreads =
        sgxlkl_enclave->max_user_threads * sizeof(*__scheduler_queue.buffer);
    max_lthreads = next_pow2(max_lthreads);

    newmpmcq(&__scheduler_queue, max_lthreads, 0);

    __init_libc(envp, argv[0]);
    __init_tls();

    size_t futex_wake_spins = sgxlkl_enclave->shared_memory.vvar ? 1 : 500;
    size_t espins = sgxlkl_enclave->espins;
    size_t esleep = sgxlkl_enclave->esleep;
    lthread_sched_global_init(espins, esleep, futex_wake_spins);

    _lthread_sched_init(sgxlkl_enclave->stacksize);

    if (lthread_create(&lt, NULL, startmain, NULL) != 0)
    {
        sgxlkl_fail("Failed to create lthread for startmain()\n");
    }

    sgxlkl_info("SEAN D ====================> 9\n");

    lthread_run();

    sgxlkl_info("SEAN D ====================> 10\n");

    return sgxlkl_exit_status;
}
