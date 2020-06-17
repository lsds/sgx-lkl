
/* Automatically generated from ../../tools/schemas/enclave-config.schema.json;
 * do not modify. */

#include "shared/sgxlkl_enclave_config_gen.h"

const sgxlkl_enclave_config_t sgxlkl_default_enclave_config = {
    .net_ip4 = "10.0.1.1",
    .net_gw4 = "10.0.1.254",
    .net_mask4 = "24",
    .hostname = "lkl",
    .tap_mtu = 0,
    .wg =
        {
            .ip = "10.0.2.1",
            .listen_port = 56002,
            .key = NULL,
            .peers = NULL,
        },
    .ethreads = 1,
    .max_user_threads = 256,
    .espins = 500,
    .esleep = 16000,
    .clock_res = {{"0000000000000001"},
                  {"0000000000000001"},
                  {"0000000000000000"},
                  {"0000000000000000"},
                  {"0000000000000001"},
                  {"00000000003d0900"},
                  {"00000000003d0900"},
                  {"0000000000000001"}},
    .stacksize = 524288,
    .oe_heap_pagecount = 8192,
    .kernel_cmd = "mem=32M",
    .sysctl = NULL,
    .run = NULL,
    .cwd = "/",
    .num_argv = 0,
    .argv = NULL,
    .num_envp = 0,
    .envp = NULL,
    .num_auxv = 0,
    .auxv = NULL,
    .num_host_import_envp = 0,
    .host_import_envp = NULL,
    .disks = NULL,
    .image_sizes =
        {
            .num_heap_pages = 262144,
            .num_stack_pages = 1024,
            .num_tcs = 8,
        },
};

typedef struct
{
    char* scope;
    char* type;
    char* description;
    char* default_value;
    char* override_var;
} sgxlkl_enclave_setting_t;

// clang-format off
static sgxlkl_enclave_setting_t sgxlkl_enclave_settings[] = {
    {"net_ip4", "char*", "IPv4 address.", "10.0.1.1", NULL},
    {"net_gw4", "char*", "IPv4 gateway address.", "10.0.1.254", NULL},
    {"net_mask4", "char*", "IPv4 netmask.", "24", NULL},
    {"hostname", "char[32]", "", "lkl", NULL},
    {"hostnet", "bool", "", "false", NULL},
    {"tap_mtu", "uint32_t", "", "0", NULL},
    {"wg.ip", "char*", "", "10.0.2.1", NULL},
    {"wg.listen_port", "uint32_t", "", "56002", NULL},
    {"wg.key", "char*", "", "None", NULL},
    {"wg.peers.key", "char*", "", "NULL", NULL},
    {"wg.peers.allowed_ips", "char*", "", "NULL", NULL},
    {"wg.peers.endpoint", "char*", "", "NULL", NULL},
    {"ethreads", "size_t", "", "1", NULL},
    {"max_user_threads", "size_t", "", "256", NULL},
    {"espins", "size_t", "", "500", NULL},
    {"esleep", "size_t", "", "16000", NULL},
    {"clock_res.resolution", "char[17]", "", "0000000000000000", NULL},
    {"stacksize", "size_t", "", "524288", NULL},
    {"oe_heap_pagecount", "size_t", "", "8192", NULL},
    {"fsgsbase", "bool", "", "true", NULL},
    {"verbose", "bool", "", "false", NULL},
    {"kernel_verbose", "bool", "", "false", NULL},
    {"kernel_cmd", "char*", "", "mem=32M", NULL},
    {"sysctl", "char*", "", "None", NULL},
    {"swiotlb", "bool", "", "true", NULL},
    {"run", "char*", "Path to the application", "None", NULL},
    {"cwd", "char*", "Path to the working directory", "/", "SGXLKL_CWD"},
    {"argv", "char**", "Application arguments", "NULL", NULL},
    {"envp", "char**", "Environment variables", "NULL", NULL},
    {"auxv", "Elf64_auxv_t*", "ELF64 Aux vector", "NULL", NULL},
    {"host_import_envp", "char**", "List of environment variables to be imported from the host", "NULL", NULL},
    {"disks.mnt", "char[256]", "Mount point", "NULL", NULL},
    {"disks.key", "uint8_t*", "Disk encryption key (hex-encoded).", "None", NULL},
    {"disks.key_id", "char*", "Name/identifier of disk encryption key.", "NULL", NULL},
    {"disks.fresh_key", "bool", "", "false", NULL},
    {"disks.roothash", "char*", "dm-verity hash.", "None", NULL},
    {"disks.roothash_offset", "size_t", "dm-verity hash offset.", "0", NULL},
    {"disks.readonly", "bool", "Whether to mount the disk read-only", "false", NULL},
    {"disks.create", "bool", "Whether to dynamically create the disk (note that an empty image file must exist).", "false", NULL},
    {"disks.size", "size_t", "Size of the ext4 filesystem in the dynamically created disk when \"create\": true.", "0", NULL},
    {"disks.overlay", "bool", "Whether to create an in-memory writable overlay for a read-only root disk", "false", NULL},
    {"image_sizes.num_heap_pages", "uint64_t", "", "262144", NULL},
    {"image_sizes.num_stack_pages", "uint64_t", "", "1024", NULL},
    {"image_sizes.num_tcs", "uint64_t", "", "8", NULL},
};

// clang-format on
