#include <shared/sgxlkl_enclave_config.h>

#pragma GCC diagnostic error "-Wmissing-field-initializers"

_Static_assert(
    sizeof(sgxlkl_enclave_config_t) == 472,
    "size of sgxlkl_enclave_config_t changed");

const sgxlkl_enclave_config_t sgxlkl_default_enclave_config = {
    .mode = 0,

    /* Network */
    .net_ip4 = DEFAULT_SGXLKL_IP4,
    .net_gw4 = DEFAULT_SGXLKL_GW4,
    .net_mask4 = DEFAULT_SGXLKL_MASK4,
    .hostname = DEFAULT_SGXLKL_HOSTNAME,
    .hostnet = DEFAULT_SGXLKL_HOSTNET,
    .tap_mtu = DEFAULT_SGXLKL_TAP_MTU,
    .wg = {.ip = DEFAULT_SGXLKL_WG_IP,
           .listen_port = DEFAULT_SGXLKL_WG_PORT,
           .key = NULL,
           .num_peers = 0,
           .peers = NULL},

    /* Scheduling */
    .max_user_threads = DEFAULT_SGXLKL_MAX_USER_THREADS,
    .espins = DEFAULT_SGXLKL_ESPINS,
    .esleep = DEFAULT_SGXLKL_ESLEEP,
    .ethreads = DEFAULT_SGXLKL_ETHREADS,
    .clock_res = {0, 0, 0, 0, 0, 0, 0, 0},

    /* Various */
    .stacksize = DEFAULT_SGXLKL_STACK_SIZE,
    .mmap_files = ENCLAVE_MMAP_FILES_NONE,
    .oe_heap_pagecount = DEFAULT_SGXLKL_OE_HEAP_PAGE_COUNT,
    .fsgsbase = true,
    .verbose = false,
    .kernel_verbose = false,
    .kernel_cmd = DEFAULT_SGXLKL_KERNEL_CMD,
    .sysctl = NULL,
    .swiotlb = false,

    /* Application */
    .app_config = {
        .run = NULL,
        .cwd = DEFAULT_SGXLKL_CWD,
        .argc = 0,
        .argv = NULL,
        .envc = 0,
        .envp = NULL,
        .auxc = 0,
        .auxv = NULL,
        .host_import_envc = 0,
        .host_import_envp = NULL,
        .exit_status = EXIT_STATUS_FULL,
        .num_disks = 0,
        .disks = NULL,
        .num_peers = 0,
        .peers = NULL,
        .sizes = {.num_heap_pages = 40000, // 262144,
                  .num_stack_pages = 1024,
                  .num_tcs = 8},
    }};

void descriptions()
{
}