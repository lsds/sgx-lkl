#include <shared/sgxlkl_enclave_config.h>

#pragma GCC diagnostic error "-Wmissing-field-initializers"

_Static_assert(
    sizeof(sgxlkl_enclave_config_t) == 448,
    "size of sgxlkl_enclave_config_t changed");

const sgxlkl_enclave_config_t sgxlkl_default_enclave_config = {
    .mode = 0,
    .stacksize = 512 * 1024,
    .mmap_files = ENCLAVE_MMAP_FILES_NONE,
    .oe_heap_pagecount = 8192, /* 8192 * 4K = 32MB */

    // /* Network */
    // uint32_t net_ip4;
    // uint32_t net_gw4;
    // int net_mask4;
    // char hostname[32];
    // bool hostnet;
    // int tap_mtu;
    // sgxlkl_enclave_wg_config_t wg;

    // /* Threading */
    // size_t max_user_threads;
    // size_t espins;
    // size_t esleep;
    // long sysconf_nproc_conf;
    // long sysconf_nproc_onln;
    // struct timespec clock_res[8];

    // bool fsgsbase;
    // bool verbose;
    // bool kernel_verbose;
    // char* kernel_cmd;
    // char* sysctl;

    // bool swiotlb; /* Option to toggle swiotlb in SW mode */

    .app_config = {
        .sizes = {.num_heap_pages = 40000, // 262144,
                  .num_stack_pages = 1024,
                  .num_tcs = 8},
    }};