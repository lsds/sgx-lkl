/* Automatically generated from ../../tools/schemas/enclave-config.schema.json; do not modify. */

#ifdef SGXLKL_ENCLAVE
#include <enclave/enclave_util.h>
#include <enclave/oe_compat.h>
#define FAIL sgxlkl_fail
#else
#include <host/sgxlkl_util.h>
#include <string.h>
#define FAIL sgxlkl_host_fail
#endif

#include "shared/sgxlkl_enclave_config_gen.h"

const char* sgxlkl_enclave_mode_t_to_string(sgxlkl_enclave_mode_t e)
{
  switch(e) {
    case UNKNOWN_MODE: return "unknown";
    case SW_DEBUG_MODE: return "sw_debug";
    case HW_DEBUG_MODE: return "hw_debug";
    case HW_RELEASE_MODE: return "hw_release";
    default: return ""; /* Unreachable */
  }
}

sgxlkl_enclave_mode_t string_to_sgxlkl_enclave_mode_t(const char *e)
{
  if (strcmp(e, "unknown") == 0) return UNKNOWN_MODE;
  if (strcmp(e, "sw_debug") == 0) return SW_DEBUG_MODE;
  if (strcmp(e, "hw_debug") == 0) return HW_DEBUG_MODE;
  if (strcmp(e, "hw_release") == 0) return HW_RELEASE_MODE;
  FAIL("unknown enum value '%s'\n", e);
  return UNKNOWN_MODE;

}

const char* sgxlkl_enclave_mmap_files_t_to_string(sgxlkl_enclave_mmap_files_t e)
{
  switch(e) {
    case ENCLAVE_MMAP_FILES_NONE: return "none";
    case ENCLAVE_MMAP_FILES_PRIVATE: return "private";
    case ENCLAVE_MMAP_FILES_SHARED: return "shared";
    default: return ""; /* Unreachable */
  }
}

sgxlkl_enclave_mmap_files_t string_to_sgxlkl_enclave_mmap_files_t(const char *e)
{
  if (strcmp(e, "none") == 0) return ENCLAVE_MMAP_FILES_NONE;
  if (strcmp(e, "private") == 0) return ENCLAVE_MMAP_FILES_PRIVATE;
  if (strcmp(e, "shared") == 0) return ENCLAVE_MMAP_FILES_SHARED;
  FAIL("unknown enum value '%s'\n", e);
  return ENCLAVE_MMAP_FILES_NONE;

}

const char* sgxlkl_exit_status_mode_t_to_string(sgxlkl_exit_status_mode_t e)
{
  switch(e) {
    case EXIT_STATUS_FULL: return "full";
    case EXIT_STATUS_BINARY: return "binary";
    case EXIT_STATUS_NONE: return "none";
    default: return ""; /* Unreachable */
  }
}

sgxlkl_exit_status_mode_t string_to_sgxlkl_exit_status_mode_t(const char *e)
{
  if (strcmp(e, "full") == 0) return EXIT_STATUS_FULL;
  if (strcmp(e, "binary") == 0) return EXIT_STATUS_BINARY;
  if (strcmp(e, "none") == 0) return EXIT_STATUS_NONE;
  FAIL("unknown enum value '%s'\n", e);
  return EXIT_STATUS_FULL;

}

const sgxlkl_enclave_config_t sgxlkl_default_enclave_config = {
    .net_ip4="10.0.1.1",
    .net_gw4="10.0.1.254",
    .net_mask4="24",
    .hostname="lkl",
    .hostnet=false,
    .tap_mtu=0,
    .wg = {
        .ip="10.0.2.1",
        .listen_port=56002,
        .key=NULL,
        .peers=NULL,
    },
    .ethreads=1,
    .max_user_threads=256,
    .espins=500,
    .esleep=16000,
    .clock_res = {{"0000000000000001"},{"0000000000000001"},{"0000000000000000"},{"0000000000000000"},{"0000000000000001"},{"00000000003d0900"},{"00000000003d0900"},{"0000000000000001"}},
    .stacksize=524288,
    .oe_heap_pagecount=8192,
    .fsgsbase=true,
    .verbose=false,
    .kernel_verbose=false,
    .kernel_cmd="mem=32M",
    .sysctl=NULL,
    .swiotlb=true,
    .cwd="/",
    .num_args=0,
    .args=NULL,
    .num_env=0,
    .env=NULL,
    .num_auxv=0,
    .auxv=NULL,
    .num_host_import_env=0,
    .host_import_env=NULL,
    .root = {
        .key_len=0,
        .key=NULL,
        .key_id=NULL,
        .roothash=NULL,
        .roothash_offset=0,
        .readonly=false,
        .overlay=false,
    },
    .mounts=NULL,
    .image_sizes = {
        .num_heap_pages=262144,
        .num_stack_pages=1024,
    },
};

// clang-format off
const sgxlkl_enclave_setting_t sgxlkl_enclave_settings[49] = {
    {"net_ip4", "char*", "IPv4 address to assign to LKL.", "10.0.1.1", "SGXLKL_IP4"},
    {"net_gw4", "char*", "IPv4 gateway to assign to LKL.", "10.0.1.254", "SGXLKL_GW4"},
    {"net_mask4", "char*", "CIDR mask for LKL to use.", "24", "SGXLKL_MASK4"},
    {"hostname", "char[32]", "Host name for LKL to use.", "lkl", "SGXLKL_HOSTNAME"},
    {"hostnet", "bool", "Hostnet", "false", "SGXLKL_HOSTNET"},
    {"tap_mtu", "uint32_t", "Sets MTU on the SGX-LKL side of the TAP interface. Must be set on the host separately (e.g. ifconfig sgxlkl_tap0 mtu 9000).", "0", "SGXLKL_TAP_MTU"},
    {"wg.ip", "char*", "IPv4 address to assign to Wireguard interface.", "10.0.2.1", "SGXLKL_WG_IP"},
    {"wg.listen_port", "uint32_t", "Port to use on eth0 interface for the Wireguard endpoint.", "56002", "SGXLKL_WG_PORT"},
    {"wg.key", "char*", "Private Wireguard key. Will be ignored in release mode in which a new key pair is generated inside the enclave on startup.", "NULL", "SGXLKL_WG_KEY"},
    {"wg.peers.key", "char*", "WG peer public key.", "NULL", NULL},
    {"wg.peers.allowed_ips", "char*", "Allowed IPs for a WG peer.", "NULL", NULL},
    {"wg.peers.endpoint", "char*", "WG peer endpoint.", "NULL", NULL},
    {"ethreads", "size_t", "Number of enclave threads.", "1", "SGXLKL_ETHREADS"},
    {"max_user_threads", "size_t", "Max. number of user-level thread inside the enclave.", "256", "SGXLKL_MAX_USER_THREADS"},
    {"espins", "size_t", "Number of spins inside scheduler before sleeping begins.", "500", "SGXLKL_ESPINS"},
    {"esleep", "size_t", "Sleep timeout in the scheduler (in ns).", "16000", "SGXLKL_ESLEEP"},
    {"clock_res.resolution", "char[17]", "", "0000000000000000", NULL},
    {"stacksize", "size_t", "Stack size of in-enclave user-level threads.", "524288", "SGXLKL_STACK_SIZE"},
    {"oe_heap_pagecount", "size_t", "OE heap limit. Build OE LIBS with -DOE_HEAP_MEMORY_ALLOCATED_SIZE=<n>", "8192", "SGXLKL_OE_HEAP_PAGE_COUNT"},
    {"fsgsbase", "bool", "", "true", NULL},
    {"verbose", "bool", "", "false", "SGXLKL_VERBOSE"},
    {"kernel_verbose", "bool", "Set to 1 to print kernel messages.", "false", "SGXLKL_KERNEL_VERBOSE"},
    {"kernel_cmd", "char*", "", "mem=32M", NULL},
    {"sysctl", "char*", "'sysctl' configurations. Semicolon-separated list of key value pairs in the form 'key1=value1;key2=value2;[...]'.", "NULL", "SGXLKL_SYSCTL"},
    {"swiotlb", "bool", "Enable DMA bounce buffer support, even in sw mode.", "true", "SGXLKL_ENABLE_SWIOTLB"},
    {"cwd", "char*", "The working directory.", "/", "SGXLKL_CWD"},
    {"args", "char**", "Application arguments.", "NULL", NULL},
    {"env", "char**", "Environment variables (VAR=VALUE).", "NULL", NULL},
    {"auxv", "Elf64_auxv_t*", "ELF64 Aux vector.", "NULL", NULL},
    {"host_import_env", "char**", "Comma-separated list of environment variables to import from the host.", "NULL", "SGXLKL_HOST_IMPORT_ENV"},
    {"root.key", "uint8_t*", "Disk encryption key (hex-encoded).", "NULL", NULL},
    {"root.key_id", "char*", "Name/identifier of disk encryption key.", "NULL", NULL},
    {"root.roothash", "char*", "dm-verity hash.", "NULL", NULL},
    {"root.roothash_offset", "size_t", "dm-verity hash offset.", "0", NULL},
    {"root.readonly", "bool", "Whether to mount the disk read-only", "false", NULL},
    {"root.overlay", "bool", "Set to 1 to create an in-memory writable overlay for a read-only root file system.", "false", "SGXLKL_HD_OVERLAY"},
    {"mounts.create", "bool", "Whether to dynamically create the disk (note that an empty image file must exist).", "false", NULL},
    {"mounts.destination", "char[256]", "Mount point", "NULL", NULL},
    {"mounts.key", "uint8_t*", "Disk encryption key (hex-encoded).", "NULL", NULL},
    {"mounts.key_id", "char*", "Name/identifier of disk encryption key.", "NULL", NULL},
    {"mounts.fresh_key", "bool", "Whether to generate a fresh key for encryption of newly created disks.", "false", NULL},
    {"mounts.readonly", "bool", "Whether to mount the disk read-only", "false", NULL},
    {"mounts.roothash", "char*", "dm-verity hash.", "NULL", NULL},
    {"mounts.roothash_offset", "size_t", "dm-verity hash offset.", "0", NULL},
    {"mounts.size", "size_t", "Size of the ext4 filesystem in the dynamically created disk when \"create\": true.", "0", NULL},
    {"image_sizes.num_heap_pages", "uint64_t", "Number of heap pages of the enclave.", "262144", NULL},
    {"image_sizes.num_stack_pages", "uint64_t", "Number of stack pages of the enclave.", "1024", NULL},
};
// clang-format on
