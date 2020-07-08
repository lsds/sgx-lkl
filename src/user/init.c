#include <libc.h>
#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_app_config.h"
#include "enclave/sgxlkl_config.h"
#include "enclave/wireguard.h"
#include "enclave/wireguard_util.h"

_Noreturn void __dls3(sgxlkl_app_config_t* conf, void* tos);

void enter_user_space(
    sgxlkl_config_t* sgxlkl_enclave,
    sgxlkl_app_config_t* app_config,
    _Atomic(enum sgxlkl_libc_state)* libc_state,
    int sgxlkl_verbose)
{
    int argc = sgxlkl_enclave->argc;
    char** argv = sgxlkl_enclave->argv;
    char** envp = argv + argc + 1;
    __init_libc(envp, argv[0]);

    SGXLKL_VERBOSE("enter\n");

    __libc_start_init();
    //a_barrier();

    /* Indicate that libc initialization has finished */
    *libc_state = libc_initialized;

    /* Setup LKL (hd, net, memory) and start kernel */

    /* SGX-LKL lthreads inherit names from their parent. Set this to "kernel"
     * temporarily to be able to identify LKL kernel threads */
    //lthread_set_funcname(lthread_self(), "kernel");
    //lkl_start_init();
    //lthread_set_funcname(lthread_self(), "sgx-lkl-init");

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

    // Add Wireguard peers
    if (wg_dev)
    {
        wgu_add_peers(wg_dev, app_config->peers, app_config->num_peers, 1);
    }
    else if (app_config->num_peers)
    {
        sgxlkl_warn("Failed to add wireguard peers: No device 'wg0' found.\n");
    }
    if (app_config->num_peers && sgxlkl_verbose)
        wgu_list_devices();

    /* Launch stage 3 dynamic linker, passing in top of stack to overwrite.
     * The dynamic linker will then load the application proper; here goes! */
    __dls3(app_config, __builtin_frame_address(0));
}