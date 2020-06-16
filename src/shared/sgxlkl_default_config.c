#include <shared/sgxlkl_enclave_config.h>

_Static_assert(
    sizeof(sgxlkl_enclave_config_t) == 464,
    "size of sgxlkl_enclave_config_t changed");

const sgxlkl_enclave_config_t sgxlkl_default_enclave_config = {
    .mode = HW_RELEASE_MODE,

    /* Network */
    .net_ip4 = "10.0.1.1",
    .net_gw4 = "10.0.1.254",
    .net_mask4 = 24,
    .hostname = "lkl",
    .hostnet = false,
    .tap_mtu = 0,
    .wg = {.ip = "10.0.2.1",
           .listen_port = 56002,
           .key = NULL,
           .num_peers = 0,
           .peers = NULL},

    /* Scheduling */
    .max_user_threads = 256,
    .espins = 500,
    .esleep = 16000,
    .ethreads = 1,
    .clock_res = {{"0000000000000001"},
                  {"0000000000000001"},
                  {"0000000000000000"},
                  {"0000000000000000"},
                  {"0000000000000001"},
                  {"00000000003d0900"},
                  {"00000000003d0900"},
                  {"0000000000000001"}},

    /* Various */
    .stacksize = 512 * 1024,
    .mmap_files = ENCLAVE_MMAP_FILES_NONE,
    .oe_heap_pagecount = 8192 /* 8192 * 4K = 32MB */,
    .fsgsbase = true,
    .verbose = false,
    .kernel_verbose = false,
    .kernel_cmd = "mem=32M",
    .sysctl = NULL,
    .swiotlb = true,

    /* Application */
    .run = NULL,
    .cwd = "/",
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

    .image_sizes = {.num_heap_pages = 262144,
                    .num_stack_pages = 1024,
                    .num_tcs = 8},
};
