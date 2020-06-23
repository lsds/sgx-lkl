#include "lkl/asm/host_ops.h"
#include "lkl/setup.h"

#define OE_BUILD_ENCLAVE
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>

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

// In internal OE header openenclave/internal/sgx/eeid_plugin.h
#define OE_FORMAT_UUID_SGX_EEID_ECDSA_P256                                \
    {                                                                     \
        0x17, 0x04, 0x94, 0xa6, 0xab, 0x23, 0x47, 0x98, 0x8c, 0x38, 0x35, \
            0x1c, 0xb0, 0xb6, 0xaf, 0x0A                                  \
    }

oe_result_t oe_sgx_eeid_attester_initialize(void);
oe_result_t oe_sgx_eeid_verifier_initialize(void);

static void get_attestation_evidence()
{
    /* Retrieve remote attestation report to exercise Azure DCAP Client
     * (currently just for testing) */
    if (sgxlkl_in_hw_debug_mode() || sgxlkl_in_hw_release_mode())
    {
        static const oe_uuid_t format_id = {OE_FORMAT_UUID_SGX_EEID_ECDSA_P256};

        oe_sgx_eeid_attester_initialize();
        oe_sgx_eeid_verifier_initialize();

        size_t evidence_buffer_size = 0;
        uint8_t* evidence_buffer = NULL;
        // Endorsements: will work once
        // https://github.com/openenclave/openenclave/pull/3166 is merged
        // size_t endorsements_buffer_size = 0;
        // uint8_t* endorsements_buffer = NULL;

        oe_result_t result = oe_get_evidence(
            &format_id,
            NULL,
            0,
            NULL,
            0,
            &evidence_buffer,
            &evidence_buffer_size,
            NULL,
            0);

        if (result != OE_OK)
            sgxlkl_fail(
                "Failed to retrieve attestation evidence: %d.\n", result);
        else
            sgxlkl_info("Successfully obtained attestation evidence\n");

        // Note: Since we're using the feature/sgx-lkl-support branch, we can
        // only verify quotes created from that branch. The verification here
        // will pass once https://github.com/openenclave/openenclave/pull/3167
        // is merged.
        oe_claim_t* claims = NULL;
        size_t claims_size = 0;
#if 0
        result = oe_verify_evidence(
            evidence_buffer,
            evidence_buffer_size,
            endorsements_buffer,
            endorsements_buffer_size,
            NULL,
            0,
            &claims,
            &claims_size);
        if (result != OE_OK)
            sgxlkl_warn("Failed to verify attestation evidence\n");
        else
        {
            sgxlkl_info("Successfully verified attestation evidence\n");
            for (size_t i = 0; i < claims_size; i++)
                sgxlkl_info(
                    "Attestation claim #%d: %s=%s\n",
                    i,
                    claims[i].name,
                    claims[i].value);
        }
#endif
        oe_free_evidence(evidence_buffer);
        // oe_free_endorsements(endorsements_buffer);
        oe_free_claims(claims, claims_size);
    }
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

    if (false)
        get_attestation_evidence();

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
        sgxlkl_fail("error: not enough heap memory for OpenEnclave heap\n");

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

    size_t futex_wake_spins = 1;
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
