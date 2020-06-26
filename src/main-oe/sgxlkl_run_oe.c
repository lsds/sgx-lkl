#define _GNU_SOURCE

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <arpa/inet.h>
#include <netinet/ip.h>

#include "enclave/enclave_mem.h"
#include "host/serialize_enclave_config.h"
#include "host/sgxlkl_params.h"
#include "host/sgxlkl_util.h"
#include "host/vio_host_event_channel.h"
#include "shared/env.h"
#include "shared/host_state.h"
#include "shared/sgxlkl_enclave_config.h"

#include "lkl/linux/virtio_net.h"

#include <openenclave/bits/exception.h>
#include <openenclave/host.h>
#include <openenclave/internal/eeid.h>

#include <host/virtio_debug.h>
#include "host/host_device_ifc.h"
#include "host/sgxlkl_u.h"

#if defined(DEBUG)
#define BUILD_INFO "[DEBUG build (-O0)]"
#elif defined(SGXLKL_RELEASE)
#define BUILD_INFO "[RELEASE build (-O3)]"
#else
#define BUILD_INFO "[NON-RELEASE build (-O3)]"
#endif

#define SGXLKL_INFO_STRING "SGX-LKL (OE) %s (%s) LKL %s %s\n"
#define SGXLKL_LAUNCHER_NAME "sgx-lkl-run-oe"

// One first empty block for bootloaders, and offset in second block
#define EXT4_MAGIC_OFFSET (1024 + 0x38)

#define MAX_KEY_FILE_SIZE_KB 8192
#define MAX_HASH_DIGITS 512
#define MAX_HASHOFFSET_DIGITS 16

#define RDFSBASE_LEN 5 // Instruction length

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

extern char __sgxlklrun_text_segment_start;

/* Function to initialize the host interface */
extern void sgxlkl_host_interface_initialization(void);

typedef uint64_t (*sgxlkl_sw_signal_handler)(oe_exception_record_t*);
static sgxlkl_sw_signal_handler _sgxlkl_sw_signal_handler;

static int rdfsbase_caused_sigill = 0;

sgxlkl_host_state_t host_state;

typedef struct ethread_args
{
    int ethread_id;
    sgxlkl_shared_memory_t* shm;
    oe_enclave_t* oe_enclave;
} ethread_args_t;

/**************************************************************************************************************************/

#ifdef DEBUG
/* Need to extract the enclave base address from OE for GDB */
typedef struct _oe_enclave_partial_t
{
    uint64_t magic;
    char* path;
    uint64_t addr;
} _oe_enclave_partial;

void __attribute__((noinline))
__gdb_hook_starter_ready(void* base_addr, int mode, char* libsgxlkl_path)
{
    __asm__ volatile("nop" : : "m"(base_addr), "m"(mode), "m"(libsgxlkl_path));
}
#endif

/**************************************************************************************************************************/

static void version()
{
    printf(
        SGXLKL_INFO_STRING,
        SGXLKL_VERSION,
        SGXLKL_GIT_COMMIT,
        LKL_VERSION,
        BUILD_INFO);
}

static void usage()
{
    version();

    printf("\n");
    printf("Usage:\n");
#ifdef SGXLKL_RELEASE
    printf(
        "%s <--hw-release> [--enclave-image={libsgxlkl.so}] "
        "[--host-config={host config file}] "
        "[--enclave-config={enclave config file}] "
        "<enclave_root_image> [executable] [args]>\n",
        SGXLKL_LAUNCHER_NAME);
    printf("\n");
    printf(
        "%-35s %s",
        "  --hw-release",
        "Run with hardware SGX enclave in release mode (secure) \t[RELEASE "
        "build only]\n");
#else
    printf(
        "%s <--sw-debug|--hw-debug> [--enclave-image={libsgxlkl file}] "
        "[--host-config={host config file}] "
        "[--enclave-config={enclave config file}] "
        "<enclave root image> <executable> [args]>\n",
        SGXLKL_LAUNCHER_NAME);
    printf("\n");
    printf(
        "%-35s %s",
        "  --sw-debug",
        "Run with emulated software enclave (insecure) \t\t[DEBUG/NON-RELEASE "
        "builds only]\n");
    printf(
        "%-35s %s",
        "  --hw-debug",
        "Run with hardware SGX enclave in debug mode (insecure) "
        "\t[DEBUG/NON-RELEASE builds only]\n");
#endif
    printf("\n");
    printf(
        "%-35s %s",
        "  --enclave-image={libsgxlkl.so}",
        "File name of enclave library containing SGX-LKL (default: "
        "${SGXLKL_ROOT}/lib/...)\n");
    printf("\n");
    printf(
        "%-35s %s",
        "  --host-config={host config file}",
        "JSON configuration file with host configuration\n");
    printf(
        "%-35s %s",
        "  --enclave-config={enclave config file}",
        "JSON configuration file with enclave configuration\n");
    printf("\n");
    printf(
        "%-35s %s",
        "  <enclave root image>",
        "File name of enclave root file system image from host\n");
    printf(
        "%-35s %s",
        "  <executable>",
        "Executable on enclave file system image to run\n");
    printf("%-35s %s", "  [args]", "Arguments to be passed to executable\n");
    printf("\n");
    printf("%-35s %s", "  --version", "Print version information\n");
    printf("%-35s %s", "  --help", "Print this help\n");
    printf(
        "%-35s %s",
        "  --help-config",
        "Print help on environment configuration variables\n");
    printf(
        "%-35s %s",
        "  --help-enclave-config",
        "Print help on variables used in enclave configuration files\n");
    printf(
        "%-35s %s",
        "  --help-tls",
        "Print help on how to enable thread-local storage support in hardware "
        "mode\n");
}

static void help_config()
{
    printf("SGX-LKL configuration via environment variables:\n");
    printf("\n");
    printf("Host options\n");
    printf("============\n");
    printf("## General ##\n");
    printf(
        "%-35s %s (default: %d)\n",
        "  SGXLKL_VERBOSE",
        "Set to 1 to enable verbose SGX-LKL output.",
        sgxlkl_default_enclave_config.verbose);
    printf(
        "%-35s %s",
        "  SGXLKL_ETHREADS_AFFINITY",
        "Specifies the CPU core affinity for enclave threads as a "
        "comma-separated list of cores to use, e.g. \"0-2,4\".\n");
    printf("## Network ##\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TAP",
        "Tap network device to use as a network interface.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TAP_OFFLOAD",
        "Set to 1 to enable partial checksum support, TSOv4, TSOv6, and "
        "mergeable receive buffers for the TAP interface.\n");
    printf("## Disk ##\n");
    printf(
        "%-35s %s",
        "  SGXLKL_HDS",
        "Secondary file system images. Comma-separated list of the format: "
        "disk1path:disk1mntpoint:disk1mode,disk2path:disk2mntpoint:disk2mode,[."
        "..].\n");
    printf(
        "%-35s %s",
        "  SGXLKL_HD_RO",
        "Set to 1 to mount the root file system as read-only.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_HD_VERITY",
        "Root hash or file path to root hash for the root file system image "
        "(Debug only).\n");
    printf(
        "%-35s %s",
        "  SGXLKL_HD_VERITY_OFFSET",
        "Offset or file path to offset of the dm-verity merkle tree on the "
        "root file system image (Debug only). If omitted and "
        "<path/to/diskimage>.hashoffset exists, this offset will be used if "
        "possible.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_HD_KEY",
        "Encryption key as passphrase or file path to a key file for the root "
        "file system image (Debug only).\n");

#ifndef SGXLKL_RELEASE
    printf("\n");
    printf("Variables to override enclave/app settings [DEBUG/NON-RELEASE "
           "build only]\n");
    printf("==================================================================="
           "======\n");

    printf(
        "  %-35s %s",
        "SGXLKL_WG_PEERS",
        "Comma-separated list of Wireguard peers in the format "
        "\"key1:allowedips1:endpointhost1:port1, key2:allowedips2:...\".\n");

    size_t n =
        sizeof(sgxlkl_enclave_settings) / sizeof(sgxlkl_enclave_setting_t);
    for (size_t i = 0; i < n; i++)
    {
        const sgxlkl_enclave_setting_t* s = &sgxlkl_enclave_settings[i];
        if (s->override_var)
            printf(
                "  %-35s %s (default: %s, overrides: %s)\n",
                s->override_var,
                s->description,
                s->default_value,
                s->scope);
    }

    printf("\n");
    printf("Debugging options [DEBUG/NON-RELEASE build only]\n");
    printf("================================================\n");
    printf("## Tracing ##\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TRACE_MMAP",
        "Trace in-enclave mmap/munmap operations.\n");
    printf("%-35s %s", "  SGXLKL_TRACE_SIGNAL", "Trace signal handling.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TRACE_THREAD",
        "Trace in-enclave user level thread scheduling.\n");
    printf("%-35s %s", "  SGXLKL_TRACE_DISK", "Trace in-enclave disk setup.\n");
    printf("%-35s %s", "  SGXLKL_TRACE_SYSCALL", "Trace all system calls.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TRACE_LKL_SYSCALL",
        "Trace in-enclave system calls handled by LKL.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TRACE_INTERNAL_SYSCALL",
        "Trace in-enclave system calls not handled by LKL (in particular "
        "mmap/mremap/munmap and futex).\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TRACE_IGNORED_SYSCALL",
        "Trace ignored system calls.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TRACE_UNSUPPORTED_SYSCALL",
        "Trace unsupported system calls.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TRACE_REDIRECT_SYSCALL",
        "Trace redirected system calls.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_TRACE_HOST_SYSCALL",
        "Trace host system calls.\n");
    printf("## Performance profiling ##\n");
    printf(
        "%-35s %s",
        "  SGXLKL_PRINT_HOST_SYSCALL_STATS",
        "Print statistics on the number of host system calls and enclave "
        "exits.\n");
    printf(
        "%-35s %s",
        "  SGXLKL_PRINT_APP_RUNTIME",
        "Print total runtime of the application excluding the enclave and "
        "SGX-LKL startup/shutdown time.\n");
#if VIRTIO_TEST_HOOK
    virtio_debug_help();
#endif // VIRTIO_TEST_HOOK
#endif // DEBUG
}

static void help_enclave_config()
{
    printf("Enclave configuration settings (attested)\n");
    printf("=========================================\n");
    size_t n =
        sizeof(sgxlkl_enclave_settings) / sizeof(sgxlkl_enclave_setting_t);
    for (size_t i = 0; i < n; i++)
    {
        const sgxlkl_enclave_setting_t* s = &sgxlkl_enclave_settings[i];
        if (s->scope)
            printf(
                "%-35s %s (default: %s)\n",
                s->scope,
                s->description,
                s->default_value);
    }
}

static void help_tls()
{
    printf("Support for Thread-Local Storage (TLS) in hardware mode\n"
           "\n"
           "On x86-64 platforms thread-local storage for applications and "
           "their initially\n"
           "available dependencies is expected to be accessible via fixed "
           "offsets from the\n"
           "current value of the FS segment base. Whenever a switch from one "
           "thread to\n"
           "another occurs, the FS segment base has to be changed accordingly. "
           "Typically\n"
           "this is done by the privileged kernel. However, with SGX the FS "
           "segment base is\n"
           "explicitly set when entering the enclave (OFSBASE field of the TCS "
           "page) and\n"
           "reset when leaving the enclave. SGX-LKL schedules application "
           "threads within\n"
           "the enclaves without leaving the enclave. It therefore needs to be "
           "able to set\n"
           "the FS segment base on context switches. This can be done with the "
           "WRFSBASE\n"
           "instruction that allows to set the FS segment base at any "
           "privilege level.\n"
           "However, this is only possible if the control register bit "
           "CR4.FSGSBASE is set\n"
           "to 1. On current Linux kernels this bit is not set as the kernel "
           "is not able to\n"
           "handle FS segment base changes by userspace applications. Note "
           "that changes to\n"
           "the segment from within an enclave are transparent to the kernel.\n"
           "\n"
           "In order to allow SGX-LKL to set the segment base from within the "
           "enclave, the\n"
           "CR4.FSGSBASE bit has to be set to 1. SGX-LKL provides a kernel "
           "module to do\n"
           "this. In order to build the module and set the CR4.FSGSBASE to 1 "
           "run the\n"
           "following:\n"
           "\n"
           "  cd tools/kmod-set-fsgsbase; make set-cr4-fsgsbase\n"
           "\n"
           "In order to set it back to 0, run:\n"
           "\n"
           "  cd tools/kmod-set-fsgsbase; make unset-cr4-fsgsbase\n"
           "\n"
           "WARNING: While using WRFSBASE within the enclave should have no "
           "impact on the\n"
           "host OS, allowing other userspace applications to use it can "
           "impact the\n"
           "stability of those applications and potentially the kernel itself. "
           "Enabling\n"
           "FSGSBASE should be done with care.\n"
           "\n");
}

#if DEBUG && VIRTIO_TEST_HOOK
/* Control the event channel notification between host & guest */

/* Signal handler to resume paused evt chn to resume guest */
static void sgxlkl_loader_signal_handler(int signo)
{
    switch (signo)
    {
        case SIGUSR2:
            /* Dump the event channel status */
            vio_host_dump_evt_chn();
            /* clear the pause flag */
            virtio_debug_set_evt_chn_state(false);
            break;
        case SIGCONT:
            /* Dump the event channel status */
            vio_host_dump_evt_chn();
            /* clear the request count, so that no further pause is executed */
            virtio_debug_set_ring_count(0);
            /* clear the pause flag */
            virtio_debug_set_evt_chn_state(false);
            break;
        default:
            sgxlkl_host_info("Handling not required\n");
    }
}
#endif // DEBUG && VIRTIO_TEST_HOOK

static void prepare_verity(
    sgxlkl_enclave_root_config_t* disk,
    const char* disk_path,
    char* verity_roothash_or_file,
    char* verity_hashoffset_or_file)
{
    if (!verity_roothash_or_file)
    {
        disk->roothash = NULL;
        disk->roothash_offset = 0;
        return;
    }

    if (access(verity_roothash_or_file, R_OK) != -1)
    {
        FILE* hf;
        char hash[MAX_HASH_DIGITS + 2];

        if (!(hf = fopen(verity_roothash_or_file, "r")))
            sgxlkl_host_fail(
                "Failed to open root hash file %s.\n", verity_roothash_or_file);

        if (!fgets(hash, MAX_HASH_DIGITS + 2, hf))
            sgxlkl_host_fail(
                "Failed to read root hash from file %s.\n",
                verity_roothash_or_file);

        /* Remove possible new line */
        char* nl = strchr(hash, '\n');
        if (nl)
            *nl = 0;

        size_t hash_len = strlen(hash);
        if (hash_len > MAX_HASH_DIGITS)
            sgxlkl_host_fail(
                "Root hash read from file %s too long! Maximum length: %d\n",
                verity_roothash_or_file,
                MAX_HASH_DIGITS);

        disk->roothash = (char*)malloc(hash_len + 1);
        strncpy(disk->roothash, hash, hash_len);
        disk->roothash[hash_len] = 0;

        fclose(hf);
    }
    else
        disk->roothash = verity_roothash_or_file;

    char* hashoffset_path;
    if (!verity_hashoffset_or_file)
    {
        size_t hashoffset_path_len =
            strlen(disk_path) + strlen(".hashoffset") + 1;
        hashoffset_path = (char*)malloc(hashoffset_path_len);
        snprintf(
            hashoffset_path,
            hashoffset_path_len,
            "%s%s",
            disk_path,
            ".hashoffset");
    }
    else
    {
        hashoffset_path = verity_hashoffset_or_file;
    }

    char* hashoffset_str;
    if (access(hashoffset_path, R_OK) != -1)
    {
        FILE* hf;
        char hashoffset_buf[MAX_HASHOFFSET_DIGITS];

        if (!(hf = fopen(hashoffset_path, "r")))
            sgxlkl_host_fail(
                "Failed to open hash offset file %s.\n", hashoffset_path);

        if (!fgets(hashoffset_buf, MAX_HASHOFFSET_DIGITS, hf))
            sgxlkl_host_fail(
                "Failed to read hash offset from file %s.\n", hashoffset_path);

        fclose(hf);

        hashoffset_str = hashoffset_buf;
    }
    else if (verity_hashoffset_or_file)
    {
        hashoffset_str = verity_hashoffset_or_file;
    }
    else
        sgxlkl_host_fail(
            "A hash offset must be set via SGXLKL_HD_VERITY_OFFSET when "
            "SGXLKL_HD_VERITY is used.\n");

    errno = 0;
    disk->roothash_offset = strtoll(hashoffset_str, NULL, 10);
    if (errno == EINVAL || errno == ERANGE)
        sgxlkl_host_fail("Failed to parse hash offset!\n");

    if (hashoffset_path != verity_hashoffset_or_file)
        free(hashoffset_path);
}

static void override_enclave_disk_config(
    sgxlkl_enclave_root_config_t* disk,
    const char* image_path,
    char* keyfile_or_passphrase,
    char* verity_roothash_or_file,
    char* verity_hashoffset_or_file)
{
    if (host_state.enclave_config.mode != HW_RELEASE_MODE)
    {
        if (keyfile_or_passphrase)
        {
            // Currently we have a single parameter for passphrases and
            // keyfiles. Determine which one it is.
            if (access(keyfile_or_passphrase, R_OK) != -1)
            {
                FILE* kf;

                if (!(kf = fopen(keyfile_or_passphrase, "rb")))
                    sgxlkl_host_fail(
                        "Failed to open keyfile %s.\n", keyfile_or_passphrase);

                fseek(kf, 0, SEEK_END);
                disk->key_len = ftell(kf);
                if (disk->key_len > MAX_KEY_FILE_SIZE_KB * 1024)
                {
                    sgxlkl_host_warn(
                        "Provided key file is larger than maximum supported "
                        "key "
                        "file size (%dkB). Only the first %dkB will be used.\n",
                        MAX_KEY_FILE_SIZE_KB,
                        MAX_KEY_FILE_SIZE_KB);
                    disk->key_len = MAX_KEY_FILE_SIZE_KB * 1024;
                }
                rewind(kf);

                disk->key = (uint8_t*)malloc((disk->key_len));
                if (!fread(disk->key, disk->key_len, 1, kf))
                    sgxlkl_host_fail(
                        "Failed to read keyfile %s.\n", keyfile_or_passphrase);

                fclose(kf);
            }
            else
            {
                disk->key_len = strlen(keyfile_or_passphrase);
                disk->key = (uint8_t*)malloc(disk->key_len);
                memcpy(disk->key, keyfile_or_passphrase, disk->key_len);
            }
        }

        prepare_verity(
            disk,
            image_path,
            verity_roothash_or_file,
            verity_hashoffset_or_file);
    }
}

void override_disk_config(const char* root_disk_path)
{
    sgxlkl_enclave_config_t* config = &host_state.enclave_config;

    /* Count disks to add */
    const char* hds_str = sgxlkl_config_str(SGXLKL_HDS);
    if (config->num_mounts == 0)
    {
        if (hds_str[0])
        {
            config->num_mounts++;
            for (int i = 0; hds_str[i]; i++)
            {
                if (hds_str[i] == ',')
                    config->num_mounts++;
            }
        }
    }

    if (!config->mounts)
    {
        config->mounts =
            calloc(config->num_mounts, sizeof(sgxlkl_enclave_mount_config_t));
        if (!config->mounts)
            sgxlkl_host_fail("out of memory\n");
    }

    /* Add root disk */
    sgxlkl_enclave_root_config_t* root_disk = &config->root;
    root_disk->readonly = sgxlkl_config_bool(SGXLKL_HD_RO);
    root_disk->overlay = sgxlkl_config_bool(SGXLKL_HD_OVERLAY);

    override_enclave_disk_config(
        root_disk,
        root_disk_path,
        sgxlkl_config_str(SGXLKL_HD_KEY),
        sgxlkl_config_str(SGXLKL_HD_VERITY),
        sgxlkl_config_str(SGXLKL_HD_VERITY_OFFSET));

    /* Secondary disks */
    if (hds_str)
    {
        char* tmp = strdup(hds_str);
        for (size_t i = 0; i < config->num_mounts && *tmp; i++)
        {
            char* hd_path = tmp;
            char* hd_mnt = strchrnul(hd_path, ':');
            *hd_mnt = '\0';
            hd_mnt++;
            char* hd_mnt_end = strchrnul(hd_mnt, ':');
            *hd_mnt_end = '\0';
            int hd_ro = hd_mnt_end[1] == '1' ? 1 : 0;

            strcpy(config->mounts[i].destination, hd_mnt);
            config->mounts[i].readonly = hd_ro;

            tmp = strchrnul(hd_mnt_end + 1, ',');
            while (*tmp == ' ' || *tmp == ',')
                tmp++;
        }
    }
}

void check_envs(const char** pres, char** envp, const char* warn_msg)
{
    char envname[128];
    for (char** env = envp; *env != 0; env++)
    {
        for (int i = 0; i < sizeof(pres) / sizeof(pres[0]); i++)
        {
            if (strncmp(pres[i], *env, strlen(pres[i])) == 0)
            {
                snprintf(
                    envname,
                    MIN(sizeof(envname), strchrnul(*env, '=') - *env + 1),
                    "%s",
                    *env);
                if (getenv_bool(envname, 0))
                {
                    fprintf(stderr, warn_msg, envname);
                }
            }
        }
    }
}

void check_envs_all(char** envp)
{
#ifndef DEBUG
    const char* dbg_pres[] = {"SGXLKL_TRACE_", "SGXLKL_PRINT_"};
    check_envs(
        dbg_pres,
        envp,
        "[   SGX-LKL  ] Warning: %s ignored in non-debug mode.\n");
#endif /* DEBUG */
}

// Assumes format --longopt[=optarg] or -shortopt[=optarg]
int getopt_sgxlkl(int argc, char* argv[], struct option long_options[])
{
    optarg = NULL;
    optopt = 0;
    if (optind >= argc)
        return -1;

    char* arg = argv[optind];
    if (arg[0] != '-')
        return -1;

    struct option* opt = long_options;
    for (; opt->name; opt++)
    {
        size_t optidx = 1;
        // Long opt
        if (arg[1] == '-' && !strncmp(opt->name, &arg[2], strlen(opt->name)))
        {
            optidx += 1 + strlen(opt->name);
            // Short opt
        }
        else if (arg[1] == opt->val)
        {
            optidx += 1;
        }
        else
            continue;

        // Handle no argument options
        if (opt->has_arg == no_argument)
        {
            if (arg[optidx])
                return -1;
            else
                break;
        }

        // Handle required argument options
        if (opt->has_arg == required_argument)
        {
            if (arg[optidx] == '=')
            {
                optidx++;
            }
            else if (arg[optidx] == '\0')
            {
                if (++optind >= argc)
                {
                    fprintf(
                        stderr, "Error: %s requires argument.\n", opt->name);
                    return '?';
                }
                else
                    optidx = 0;
            }
        }
        optarg = &argv[optind][optidx];
        break;
    }

    if (opt)
    {
        optind++;
        return opt->val;
    }
    else
        return -1;
}

/* Determines path of libsgxlkl.so.signed */
void get_signed_libsgxlkl_path(char* path_buf, size_t len)
{
    /* Look for libsgxlkl.so.signed in:
     *  1. .
     *  2. ../lib
     *  3. /lib
     *  4. /usr/local/lib
     *  5. /usr/lib
     *
     * NOTE: The code below relies on the fact that relative paths
     * are checked first.
     */
    char* search_in = ".:../lib:/lib:/usr/local/lib:/usr/lib";

    ssize_t q;
    char* path_sep;
    q = readlink("/proc/self/exe", path_buf, len);

    // Add null terminator to path. Without this, path_buf may end with random
    // characters, and if '/' is one of them, strrchr below will return wrong
    // substring.
    if (q > 0 && q < PATH_MAX)
        path_buf[q] = '\0';

    if (q <= 0 || (path_sep = strrchr(path_buf, '/')) == NULL)
        sgxlkl_host_fail("Unable to determine path of SGX-LKL run binary.\n");

    char* base = search_in;
    size_t base_len = 0;
    while ((base_len = strcspn(base, ":")) > 0)
    {
        // Relative or absolute path
        char* buf;
        size_t max_len;
        if (!strncmp(base, ".", 1))
        {
            buf = path_sep + 1;
            max_len = len - (path_sep + 1 - path_buf);
        }
        else
        {
            buf = path_buf;
            max_len = len;
        }

        if (snprintf(
                buf,
                max_len,
                "%.*s/%s",
                (int)base_len,
                base,
                "libsgxlkl.so.signed") < max_len)
        {
            // If accessible, path found.
            if (!access(path_buf, R_OK))
                return;
        }

        base += base_len;
        base += strspn(base, ":");
    }

    sgxlkl_host_fail("Unable to locate libsgxlkl.so.signed\n");
}

void mk_clock_res_string(int clock)
{
    sgxlkl_enclave_config_t* econf = &host_state.enclave_config;
    size_t sz = sizeof(sgxlkl_clock_res_config_t);
    struct timespec tmpt;
    char tmps[8 * 2 * 2 + 1];
    clock_getres(clock, &tmpt);
    snprintf(tmps, sizeof(tmps), "%08lx%08lx", tmpt.tv_sec, tmpt.tv_nsec);
    memcpy(econf->clock_res[clock].resolution, tmps, sz);
}

void set_clock_res(bool have_enclave_config)
{
    /* The enclave config file has a specified default for these settings,
     * so we auto-detect them only if we don't have an enclave config file.
     */

    if (!have_enclave_config)
    {
        mk_clock_res_string(CLOCK_REALTIME);
        mk_clock_res_string(CLOCK_MONOTONIC);
        mk_clock_res_string(CLOCK_MONOTONIC_RAW);
        mk_clock_res_string(CLOCK_REALTIME_COARSE);
        mk_clock_res_string(CLOCK_MONOTONIC_COARSE);
        mk_clock_res_string(CLOCK_BOOTTIME);
    }
}

static void rdfsbase_sigill_handler(int sig, siginfo_t* si, void* data)
{
    rdfsbase_caused_sigill = 1;

    // Skip instruction
    ucontext_t* uc = (ucontext_t*)data;
    uc->uc_mcontext.gregs[REG_RIP] += RDFSBASE_LEN;
}

/* Checks whether we can us FSGSBASE instructions within the enclave
   NOTE: This overrides previously set SIGILL handlers! */
void set_tls(bool have_enclave_config)
{
    sgxlkl_enclave_config_t* econf = &host_state.enclave_config;

    if (econf->mode != SW_DEBUG_MODE)
    {
        if (have_enclave_config && !econf->fsgsbase)
            sgxlkl_host_fail("fsgsbase cannot be disabled in hardware mode.");

        // We need to check whether we can support TLS in hardware mode or not
        // This is only possible if control register bit CR4.FSGSBASE is set
        // that allows us to set the FS segment base from userspace when context
        // switching between lthreads within the enclave.

        // All SGX-capabale CPUs should support the FSGSBASE feature, so we
        // won't check CPUID here. However, we do have to check whether the
        // control register bit is set. Currently, the only way to do this seems
        // to be by actually using one of the FSGSBASE instructions to check
        // whether it causes a #UD exception.
        struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = rdfsbase_sigill_handler;
        if (sigaction(SIGILL, &sa, NULL) == -1)
        {
            sgxlkl_host_warn(
                "Failed to register SIGILL handler. Only limited thread-local "
                "storage support will be available.\n");
            return;
        }

        // WRFSBASE instruction can always be used inside the enclave. It will
        // either be a legal instruction, or it will be emulated by handling
        // the SIGILL in `oecore` first-pass exception handler.
        econf->fsgsbase = 1;

        // If the following instruction causes a segfault, WRFSBASE will be
        // emulated inside the enclave. This can be a performance penalty.
        volatile unsigned long x;
        __asm__ volatile("rdfsbase %0" : "=r"(x));
    }
    else
    {
        assert(econf->mode == SW_DEBUG_MODE);
        if (have_enclave_config && econf->fsgsbase != 0)
            sgxlkl_host_warn("disabling fsgsbase in sw-debug mode, despite it "
                             "being enabled in enclave config.");
        econf->fsgsbase = 0;
    }

    sgxlkl_host_verbose(
        "HW TLS support: econf->fsgsbase=%i\n", econf->fsgsbase);
    if (rdfsbase_caused_sigill)
    {
        sgxlkl_host_warn("WRFSBASE instruction raises SIGILL and will be "
                         "emulated within the enclave. "
                         "Run `sgx-lkl-run-oe -t` for information about how to "
                         "fix this performance issue.\n");
    }
}

/* Override wireguard enclave configuration */
void override_enclave_wg_config()
{
    sgxlkl_enclave_wg_config_t* wg = &host_state.enclave_config.wg;

    if (sgxlkl_configured(SGXLKL_WG_IP))
        wg->ip = sgxlkl_config_str(SGXLKL_WG_IP);

    if (sgxlkl_configured(SGXLKL_WG_PORT))
        wg->listen_port = (uint16_t)sgxlkl_config_uint64(SGXLKL_WG_PORT);

    if (sgxlkl_configured(SGXLKL_WG_KEY))
        wg->key = sgxlkl_config_str(SGXLKL_WG_KEY);

    if (sgxlkl_configured(SGXLKL_WG_PEERS))
    {
        int num_peers = 0;
        char* peers_str = sgxlkl_config_str(SGXLKL_WG_PEERS);
        if (peers_str[0])
        {
            num_peers++;
            for (int i = 0; peers_str[i]; i++)
            {
                if (peers_str[i] == ',')
                    num_peers++;
            }
        }

        wg->num_peers = 0;
        if (!num_peers)
            return;

        // Allocate space for wg peer configuration
        wg->peers = (sgxlkl_enclave_wg_peer_config_t*)malloc(
            sizeof(sgxlkl_enclave_wg_peer_config_t) * num_peers);
        while (*peers_str)
        {
            char* key = peers_str;
            char* ips = strchrnul(key, ':');
            *ips = '\0';
            ips++;

            char* ips_end = strchrnul(ips, ':');
            // another ':', possible endpoint following, need to advance string
            if (*ips_end == ':')
            {
                *ips_end = '\0';
                ips_end++;
            }

            char* endpoint = ips_end;
            peers_str = strchrnul(endpoint, ',');
            if (*peers_str == ',')
            {
                *peers_str = '\0';
                peers_str++;
                while (*peers_str == ' ' || *peers_str == ',')
                    peers_str++;
            }

            wg->peers[wg->num_peers].key = key;
            wg->peers[wg->num_peers].allowed_ips = ips;
            wg->peers[wg->num_peers].endpoint = endpoint;
            wg->num_peers++;
        }
    }
}

static void register_hd(sgxlkl_host_disk_state_t* disk, size_t idx)
{
    sgxlkl_host_verbose(
        "Registering disk %lu (path='%s', mnt='%s', [%s])\n",
        idx,
        disk->image_path,
        disk->mnt,
        disk->readonly ? "RO" : "RW");

    if (strlen(disk->mnt) > SGXLKL_DISK_MNT_MAX_PATH_LEN)
        sgxlkl_host_fail(
            "Mount path for disk %lu too long (maximum length is %d): \"%s\"\n",
            idx,
            SGXLKL_DISK_MNT_MAX_PATH_LEN,
            disk->mnt);

    int fd = open(disk->image_path, disk->readonly ? O_RDONLY : O_RDWR);
    if (fd == -1)
        sgxlkl_host_fail(
            "Unable to open disk file %s for %s access: %s\n",
            disk->image_path,
            disk->readonly ? "read" : "read/write",
            strerror(errno));

    struct stat disk_stat;
    fstat(fd, &disk_stat);

    off_t size = disk_stat.st_size;
    if ((disk_stat.st_mode & S_IFMT) == S_IFBLK)
    {
        if (ioctl(fd, BLKGETSIZE64, &size) < 0)
        {
            sgxlkl_host_fail(
                "Failed to get block device size of %s: %s\n",
                disk->image_path,
                strerror(errno));
        }
    }

    char* disk_mmap = mmap(
        NULL,
        size,
        PROT_READ | (disk->readonly ? 0 : PROT_WRITE),
        MAP_SHARED,
        fd,
        0);
    if (disk_mmap == MAP_FAILED)
        sgxlkl_host_fail(
            "Could not map memory for disk image: %s\n", strerror(errno));

    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        sgxlkl_host_fail("fcntl(disk_fd, F_GETFL)");

    int res = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (res == -1)
        sgxlkl_host_fail("fcntl(disk_fd, F_SETFL)");

    disk->fd = fd;
    disk->mmap = disk_mmap;
    disk->size = size;

    blk_device_init(disk, idx, host_state.enclave_config.swiotlb);
}

static void register_hds(char* root_hd)
{
    size_t num_disks = host_state.num_disks;
    if (num_disks == 0)
        sgxlkl_host_fail("no disks in host config");

    sgxlkl_shared_memory_t* shm = &host_state.shared_memory;
    shm->num_virtio_blk_dev = host_state.num_disks;
    shm->virtio_blk_dev_mem = calloc(host_state.num_disks, sizeof(void*));
    shm->virtio_blk_dev_names = calloc(host_state.num_disks, sizeof(char*));

    if (!shm->virtio_blk_dev_mem || !shm->virtio_blk_dev_names)
        sgxlkl_host_fail("out of memory\n");

    for (size_t i = 0; i < num_disks; i++)
    {
        sgxlkl_host_disk_state_t* disk = &host_state.disks[i];
        register_hd(disk, i);
        strcpy(shm->virtio_blk_dev_names[i], disk->mnt);
    }
}

static void register_net()
{
    if (host_state.net_fd != 0)
        sgxlkl_host_fail("Multiple network interfaces not supported yet\n");

    // Open tap device FD
    const char* tapstr = host_state.config.tap_device;
    if (tapstr == NULL || strlen(tapstr) == 0)
    {
        sgxlkl_host_verbose(
            "No tap device specified, networking will not be available.\n");
        return;
    }
    struct ifreq ifr;
    strncpy(ifr.ifr_name, tapstr, IFNAMSIZ);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    int vnet_hdr_sz = 0;
    if (host_state.config.tap_offload)
    {
        ifr.ifr_flags |= IFF_VNET_HDR;
        vnet_hdr_sz = sizeof(struct lkl_virtio_net_hdr_v1);
    }

    host_state.net_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (host_state.net_fd == -1)
        sgxlkl_host_fail(
            "TUN network device unavailable, open(\"/dev/net/tun\") failed");

    if (ioctl(host_state.net_fd, TUNSETIFF, &ifr) == -1)
        sgxlkl_host_fail(
            "Tap device %s unavailable, ioctl(\"/dev/net/tun\"), TUNSETIFF) "
            "failed: %s\n",
            tapstr,
            strerror(errno));

    if (vnet_hdr_sz &&
        ioctl(host_state.net_fd, TUNSETVNETHDRSZ, &vnet_hdr_sz) != 0)
        sgxlkl_host_fail(
            "Failed to TUNSETVNETHDRSZ: /dev/net/tun: %s\n", strerror(errno));

    int offload_flags = 0;
    if (host_state.config.tap_offload)
        offload_flags = TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_CSUM;

    if (ioctl(host_state.net_fd, TUNSETOFFLOAD, offload_flags) != 0)
        sgxlkl_host_fail(
            "Failed to TUNSETOFFLOAD: /dev/net/tun: %s\n", strerror(errno));
}

static void sgxlkl_cleanup(void)
{
    // Close disk image fds
    while (host_state.num_disks)
    {
        close(host_state.disks[--host_state.num_disks].fd);
    }
    free(host_state.shared_memory.virtio_blk_dev_mem);
    free(host_state.shared_memory.virtio_blk_dev_names);
}

static void serialize_ucontext(
    const oe_context_t* octx,
    struct ucontext_t* uctx)
{
    uctx->uc_mcontext.gregs[REG_RAX] = octx->rax;
    uctx->uc_mcontext.gregs[REG_RBX] = octx->rbx;
    uctx->uc_mcontext.gregs[REG_RCX] = octx->rcx;
    uctx->uc_mcontext.gregs[REG_RDX] = octx->rdx;
    uctx->uc_mcontext.gregs[REG_RBP] = octx->rbp;
    uctx->uc_mcontext.gregs[REG_RSP] = octx->rsp;
    uctx->uc_mcontext.gregs[REG_RDI] = octx->rdi;
    uctx->uc_mcontext.gregs[REG_RSI] = octx->rsi;
    uctx->uc_mcontext.gregs[REG_R8] = octx->r8;
    uctx->uc_mcontext.gregs[REG_R9] = octx->r9;
    uctx->uc_mcontext.gregs[REG_R10] = octx->r10;
    uctx->uc_mcontext.gregs[REG_R11] = octx->r11;
    uctx->uc_mcontext.gregs[REG_R12] = octx->r12;
    uctx->uc_mcontext.gregs[REG_R13] = octx->r13;
    uctx->uc_mcontext.gregs[REG_R14] = octx->r14;
    uctx->uc_mcontext.gregs[REG_R15] = octx->r15;
    uctx->uc_mcontext.gregs[REG_RIP] = octx->rip;
}

static void deserialize_ucontext(
    const struct ucontext_t* uctx,
    oe_context_t* octx)
{
    octx->rax = uctx->uc_mcontext.gregs[REG_RAX];
    octx->rbx = uctx->uc_mcontext.gregs[REG_RBX];
    octx->rcx = uctx->uc_mcontext.gregs[REG_RCX];
    octx->rdx = uctx->uc_mcontext.gregs[REG_RDX];
    octx->rbp = uctx->uc_mcontext.gregs[REG_RBP];
    octx->rsp = uctx->uc_mcontext.gregs[REG_RSP];
    octx->rdi = uctx->uc_mcontext.gregs[REG_RDI];
    octx->rsi = uctx->uc_mcontext.gregs[REG_RSI];
    octx->r8 = uctx->uc_mcontext.gregs[REG_R8];
    octx->r9 = uctx->uc_mcontext.gregs[REG_R9];
    octx->r10 = uctx->uc_mcontext.gregs[REG_R10];
    octx->r11 = uctx->uc_mcontext.gregs[REG_R11];
    octx->r12 = uctx->uc_mcontext.gregs[REG_R12];
    octx->r13 = uctx->uc_mcontext.gregs[REG_R13];
    octx->r14 = uctx->uc_mcontext.gregs[REG_R14];
    octx->r15 = uctx->uc_mcontext.gregs[REG_R15];
    octx->rip = uctx->uc_mcontext.gregs[REG_RIP];
}

static void sgxlkl_sw_mode_signal_handler(
    int sig,
    siginfo_t* si,
    void* sig_data)
{
    oe_exception_record_t oe_exception_record = {0};
    oe_context_t oe_context = {0};
    uint32_t oe_code = 0;

    ucontext_t* context = (ucontext_t*)sig_data;
    deserialize_ucontext(context, &oe_context);

    switch (sig)
    {
        case SIGFPE:
            oe_code = OE_EXCEPTION_DIVIDE_BY_ZERO;
            break;
        case SIGSEGV:
            oe_code = OE_EXCEPTION_PAGE_FAULT;
            break;
        case SIGILL:
            oe_code = OE_EXCEPTION_ILLEGAL_INSTRUCTION;
            break;
        case SIGBUS:
            oe_code = OE_EXCEPTION_MISALIGNMENT;
            break;
        case SIGTRAP:
            oe_code = OE_EXCEPTION_BREAKPOINT;
            break;
    }

    oe_exception_record.code = oe_code;
    oe_exception_record.flags = 0;
    oe_exception_record.address = (uint64_t)si->si_addr;
    oe_exception_record.context = &oe_context;

    _sgxlkl_sw_signal_handler(&oe_exception_record);
    serialize_ucontext(&oe_context, context);
}

void register_enclave_signal_handler(void* signal_handler)
{
    _sgxlkl_sw_signal_handler = (sgxlkl_sw_signal_handler)signal_handler;
}

/* SGX-LKL requires special signal handing for SW mode as OE
 * does not support signal handling for SW mode. */
static void setup_sw_mode_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sgxlkl_sw_mode_signal_handler;
    if (sigaction(SIGILL, &sa, NULL) == -1)
        sgxlkl_host_fail("Failed to register SIGILL handler\n");

    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        sgxlkl_host_fail("Failed to register SIGSEGV handler\n");

    if (sigaction(SIGFPE, &sa, NULL) == -1)
        sgxlkl_host_fail("Failed to register SIGFPE handler\n");

    if (sigaction(SIGBUS, &sa, NULL) == -1)
        sgxlkl_host_fail("Failed to register SIGBUS handler\n");

    if (sigaction(SIGTRAP, &sa, NULL) == -1)
        sgxlkl_host_fail("Failed to register SIGTRAP handler\n");
}

/* Parses the string provided as config for CPU affinity specifications. The
 * specification must consist of a comma-separated list of core IDs. It can
 * contain ranges. For example, "0-2,4" is a valid specification.
 * This function will allocate an array of all specified core IDs and stores
 * it's address at **cores. The number of valid array entries is stored at
 * cores_len.
 *
 * The memory allocated for the array should be free'd by the caller.
 */
void parse_cpu_affinity_params(char* config, int** cores, size_t* cores_len)
{
    *cores = NULL;
    *cores_len = 0;

    if (!config || !strlen(config))
    {
        return;
    }

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    // For simplicitly we allocate an array of size nproc to hold all cores
    // that are to be used. When the affinity is set to use a subset of cores,
    // *cores_len will reflect this.
    *cores = malloc(sizeof(int) * nproc);

    char* curr_ptr = config;
    long val = 0, range_start = -1;
    while (*curr_ptr && *cores_len < nproc)
    {
        switch (*curr_ptr)
        {
            case '0' ... '9':
            {
                // strtol will advance curr_ptr to the next non-digit character.
                val = strtol(curr_ptr, &curr_ptr, 10);
                if (val < 0 || val >= nproc)
                {
                    fprintf(
                        stderr,
                        "[    SGX-LKL   ] Invalid CPU affinity range: %s, "
                        "value %lu is larger or equal than the number of "
                        "available cores (%lu).\n",
                        config,
                        val,
                        nproc);
                    return;
                }
                else if (range_start < 0)
                {
                    (*cores)[(*cores_len)++] = (int)val;
                }
                else
                { // Range (range_start has already been added)
                    for (; val > range_start && *cores_len < nproc; val--)
                    {
                        (*cores)[(*cores_len)++] = (int)val;
                    }
                    range_start = -1;
                }
                break;
            }
            case ',':
                curr_ptr++;
                break;
            case '-':
                range_start = val;
                curr_ptr++;
                break;
            default:
                fprintf(
                    stderr,
                    "[    SGX-LKL   ] Invalid CPU affinity range: %s\n",
                    config);
                return;
        }
    }
}

static _Atomic(bool) first_thread = true;

void* ethread_init(ethread_args_t* args)
{
    oe_result_t result = sgxlkl_ethread_init(args->oe_enclave);
    bool current_value = true;
    if (sgxlkl_config_bool(SGXLKL_VERBOSE) &&
        atomic_compare_exchange_strong(&first_thread, &current_value, false))
    {
        sgxlkl_host_verbose("");
    }
    sgxlkl_host_verbose_raw("ethread (%i: %u) ", args->ethread_id, result);
    if (result != OE_OK)
    {
        sgxlkl_host_fail(
            "sgxlkl_ethread_init() failed (id=%i result=%u (%s))\n",
            args->ethread_id,
            result,
            oe_result_str(result));
    }
    return NULL;
}

void* enclave_init(ethread_args_t* args)
{
    sgxlkl_host_verbose(
        "sgxlkl_enclave_init(ethread_id=%i)\n", args->ethread_id);
    int exit_status;
    oe_result_t result =
        sgxlkl_enclave_init(args->oe_enclave, &exit_status, args->shm);
    bool current_value = true;
    if (sgxlkl_config_bool(SGXLKL_VERBOSE) &&
        atomic_compare_exchange_strong(&first_thread, &current_value, false))
    {
        sgxlkl_host_verbose("");
    }
    sgxlkl_host_verbose_raw(
        "init (%i: %u exit=%i) ", args->ethread_id, result, exit_status);

    if (result != OE_OK)
    {
        sgxlkl_host_fail(
            "sgxlkl_ethread_init() failed (ethread_id=%i result=%u (%s))\n",
            args->ethread_id,
            result,
            oe_result_str(result));
    }

    return (void*)(long)exit_status;
}

/* Creates an SGX-LKL enclave with enclave configuration in the EEID. */
void _create_enclave(
    char* libsgxlkl,
    uint32_t oe_flags,
    oe_enclave_t** oe_enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_setting_t setting;
    setting.setting_type = OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA;

    char* buffer = NULL;
    size_t buffer_size = 0;

    serialize_enclave_config(&host_state.enclave_config, &buffer, &buffer_size);

    oe_eeid_t* eeid = NULL;
    oe_create_eeid_sgx(buffer_size, &eeid);
    sgxlkl_enclave_config_t* econf = &host_state.enclave_config;
    oe_enclave_size_settings_t oe_sizes = {
        .num_heap_pages = econf->image_sizes.num_heap_pages,
        .num_stack_pages = econf->image_sizes.num_stack_pages,
        .num_tcs = econf->ethreads,
    };

    eeid->size_settings = oe_sizes;
    memcpy(eeid->data, buffer, buffer_size);

    setting.u.eeid = eeid;

    result = oe_create_sgxlkl_enclave(
        libsgxlkl, OE_ENCLAVE_TYPE_SGX, oe_flags, &setting, 1, oe_enclave);

    free(eeid);

    sgxlkl_host_verbose_raw("result=%u (%s)\n", result, oe_result_str(result));

    if (result != OE_OK)
        sgxlkl_host_fail("Could not initialise enclave\n");
}

void find_root_disk_file(int* argc, char*** argv, char** root_hd)
{
    // Determine path to root disk. Either configured via env/json config or
    // as first command line argument.
    if (sgxlkl_configured(SGXLKL_HD))
    {
        if (root_hd)
            *root_hd = sgxlkl_config_str(SGXLKL_HD);
    }
    else if (argc > 0)
    {
        if (root_hd)
            *root_hd = (*argv)[0];
        (*argc)--;
        (*argv)++;
    }
    else
    {
        sgxlkl_host_err(
            "Insufficient arguments: no root disk image path provided.\n");
        printf("\n");
        usage(SGXLKL_LAUNCHER_NAME);
        exit(EXIT_FAILURE);
    }
}

void enclave_config_from_file(const char* filename)
{
    int fd;
    if ((fd = open(filename, O_RDONLY)) < 0)
        sgxlkl_host_fail("Failed to open %s: %s.\n", filename, strerror(errno));

    off_t len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char* buf = (char*)malloc(len + 1);
    ssize_t ret;
    int off = 0;
    while ((ret = read(fd, &buf[off], len - off)) > 0)
    {
        off += ret;
    }
    buf[len] = 0;
    close(fd);

    if (ret < 0)
        sgxlkl_host_fail("Failed to read %s: %s.\n", filename, strerror(errno));

    if (sgxlkl_read_enclave_config(buf, &host_state.enclave_config, false))
        sgxlkl_host_fail("Failed to parse enclave config '%s'\n", filename);
}

void override_enclave_config(
    int argc,
    char** argv,
    const char* root_disk_file,
    sgxlkl_enclave_mode_t enclave_mode_cmdline)
{
    sgxlkl_enclave_config_t* econf = &host_state.enclave_config;

    if (enclave_mode_cmdline != UNKNOWN_MODE)
        econf->mode = enclave_mode_cmdline;

    if (sgxlkl_configured(SGXLKL_OE_HEAP_PAGE_COUNT))
        econf->oe_heap_pagecount =
            sgxlkl_config_uint64(SGXLKL_OE_HEAP_PAGE_COUNT);

    if (sgxlkl_configured(SGXLKL_STACK_SIZE))
        econf->stacksize = sgxlkl_config_uint64(SGXLKL_STACK_SIZE);

    if (sgxlkl_configured(SGXLKL_MAX_USER_THREADS))
        econf->max_user_threads = sgxlkl_config_uint64(SGXLKL_MAX_USER_THREADS);

    if (sgxlkl_configured(SGXLKL_ESPINS))
        econf->espins = sgxlkl_config_uint64(SGXLKL_ESPINS);

    if (sgxlkl_configured(SGXLKL_ESLEEP))
        econf->esleep = sgxlkl_config_uint64(SGXLKL_ESLEEP);

    if (sgxlkl_configured(SGXLKL_VERBOSE))
        econf->verbose = sgxlkl_config_bool(SGXLKL_VERBOSE);

    if (sgxlkl_configured(SGXLKL_KERNEL_VERBOSE))
        econf->kernel_verbose = sgxlkl_config_bool(SGXLKL_KERNEL_VERBOSE);

    if (sgxlkl_configured(SGXLKL_CMDLINE))
        econf->kernel_cmd = sgxlkl_config_str(SGXLKL_CMDLINE);

    if (sgxlkl_configured(SGXLKL_SYSCTL))
        econf->sysctl = sgxlkl_config_str(SGXLKL_SYSCTL);

    if (sgxlkl_configured(SGXLKL_ENABLE_SWIOTLB))
        econf->swiotlb = sgxlkl_config_bool(SGXLKL_ENABLE_SWIOTLB);

    if (sgxlkl_configured(SGXLKL_MMAP_FILES))
    {
        char* mmap_files = sgxlkl_config_str(SGXLKL_MMAP_FILES);
        econf->mmap_files =
            !strcmp(mmap_files, "Shared")
                ? ENCLAVE_MMAP_FILES_SHARED
                : (!strcmp(mmap_files, "Private") ? ENCLAVE_MMAP_FILES_PRIVATE
                                                  : ENCLAVE_MMAP_FILES_NONE);
    }

    if (sgxlkl_configured(SGXLKL_ETHREADS))
        econf->ethreads = sgxlkl_config_uint64(SGXLKL_ETHREADS);

    if (sgxlkl_configured(SGXLKL_IP4))
        econf->net_ip4 = sgxlkl_config_str(SGXLKL_IP4);

    if (sgxlkl_configured(SGXLKL_GW4))
        econf->net_gw4 = sgxlkl_config_str(SGXLKL_GW4);

    if (sgxlkl_configured(SGXLKL_MASK4))
        econf->net_mask4 = sgxlkl_config_str(SGXLKL_MASK4);

    if (sgxlkl_configured(SGXLKL_HOSTNAME))
        strcpy(econf->hostname, sgxlkl_config_str(SGXLKL_HOSTNAME));

    if (sgxlkl_configured(SGXLKL_TAP_MTU))
        econf->tap_mtu = (int)sgxlkl_config_uint64(SGXLKL_TAP_MTU);

    if (sgxlkl_configured(SGXLKL_HOSTNET))
        econf->hostnet = sgxlkl_config_bool(SGXLKL_HOSTNET);

    override_enclave_wg_config();

    if (sgxlkl_configured(SGXLKL_HDS) || sgxlkl_configured(SGXLKL_HD_RO) ||
        sgxlkl_configured(SGXLKL_HD_OVERLAY) ||
        sgxlkl_configured(SGXLKL_HD_KEY) ||
        sgxlkl_configured(SGXLKL_HD_VERITY) ||
        sgxlkl_configured(SGXLKL_HD_VERITY_OFFSET))
        override_disk_config(root_disk_file);

    if (argv && argc > 0)
    {
        econf->num_args = argc;
        econf->args = argv;
    }

    if (sgxlkl_configured(SGXLKL_HOST_IMPORT_ENV))
    {
        char* import_vars = strdup(sgxlkl_config_str(SGXLKL_HOST_IMPORT_ENV));
        econf->num_host_import_env = 0;
        char* begin = import_vars;
        bool end = import_vars == NULL;
        for (char* p = import_vars; !end; p++)
            if (*p == ',' || *p == 0)
            {
                econf->host_import_env = realloc(
                    econf->host_import_env,
                    sizeof(char*) * (econf->num_host_import_env + 1));
                if (*p == 0)
                    end = true;
                *p = 0;
                econf->host_import_env[econf->num_host_import_env++] =
                    strdup(begin);
                begin = p + 1;
            }
        free(import_vars);
    }
}

void host_config_from_params(char* root_disk_path)
{
    host_state.config.tap_device = sgxlkl_config_str(SGXLKL_TAP);
    host_state.config.thread_affinity =
        sgxlkl_config_str(SGXLKL_ETHREADS_AFFINITY);
    host_state.config.tap_offload = sgxlkl_config_bool(SGXLKL_TAP_OFFLOAD);

    if (!root_disk_path)
        sgxlkl_host_fail("no root disk file\n");

    /* Add root disk */
    host_state.num_disks = 1;
    sgxlkl_host_disk_state_t* root_disk = &host_state.disks[0];
    strcpy(root_disk->mnt, "/");
    root_disk->image_path = root_disk_path;

    /* Secondary disks */
    const char* hds_str = sgxlkl_config_str(SGXLKL_HDS);
    char* tmp = strdup(hds_str);
    for (size_t i = 1; *tmp; i++)
    {
        char* hd_path = tmp;
        char* hd_mnt = strchrnul(hd_path, ':');
        *hd_mnt = '\0';
        hd_mnt++;
        char* hd_mnt_end = strchrnul(hd_mnt, ':');
        *hd_mnt_end = '\0';
        int hd_ro = hd_mnt_end[1] == '1' ? 1 : 0;

        host_state.disks[i].image_path = hd_path;
        strcpy(host_state.disks[i].mnt, hd_mnt);
        host_state.disks[i].readonly = hd_ro;

        tmp = strchrnul(hd_mnt_end + 1, ',');
        while (*tmp == ' ' || *tmp == ',')
            tmp++;

        host_state.num_disks++;
        if (host_state.num_disks >= HOST_MAX_DISKS)
            sgxlkl_host_fail("too many disks\n");
    }
}

void host_config_from_file(char* filename, char* root_disk_path)
{
    char* err = NULL;
    if (sgxlkl_parse_params_from_file(filename, &err) < 0)
        sgxlkl_host_fail(
            "Error parsing host config file '%s': %s\n", filename, err);

    if (sgxlkl_configured(SGXLKL_HD))
        root_disk_path = sgxlkl_config_str(SGXLKL_HD);

    host_config_from_params(root_disk_path);
}

void host_config_from_cmdline(char* root_disk_path)
{
    host_config_from_params(root_disk_path);
}

int main(int argc, char* argv[], char* envp[])
{
    char* host_config_path = NULL;
    char* enclave_config_path = NULL;
    char libsgxlkl[PATH_MAX];
    const sgxlkl_enclave_config_t* econf = &host_state.enclave_config;
    char* root_hd = NULL;
    pthread_t* sgxlkl_threads;
    pthread_t* host_vdisk_task;
    pthread_t* host_netdev_task;
    pthread_t* host_console_task;
    pthread_t* host_timerdev_task;
    int* ethreads_cores;
    size_t ethreads_cores_len;
    pthread_attr_t eattr;
    cpu_set_t set;
    void* return_value;
    bool enclave_image_provided = false;

    oe_enclave_t* oe_enclave = NULL;
    uint32_t oe_flags = 0;

    int c;

#if DEBUG && VIRTIO_TEST_HOOK
    signal(SIGUSR2, sgxlkl_loader_signal_handler);
    signal(SIGCONT, sgxlkl_loader_signal_handler);
    virtio_debug_init();
#endif // DEBUG && VIRTIO_TEST_HOOK

    static struct option long_options[] = {
        {"sw-debug", no_argument, 0, SW_DEBUG_MODE},
        {"hw-debug", no_argument, 0, HW_DEBUG_MODE},
        {"hw-release", no_argument, 0, HW_RELEASE_MODE},
        {"version", no_argument, 0, 'v'},
        {"help-config", no_argument, 0, 'C'},
        {"help-enclave-config", no_argument, 0, 'E'},
        {"help-tls", no_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {"enclave-image", required_argument, 0, 'e'},
        {"host-config", required_argument, 0, 'H'},
        {"enclave-config", required_argument, 0, 'c'},
        {0, 0, 0, 0}};

    host_state.enclave_config = sgxlkl_default_enclave_config;
    sgxlkl_enclave_mode_t enclave_mode_cmdline = UNKNOWN_MODE;

    while ((c = getopt_sgxlkl(argc, argv, long_options)) != -1)
    {
        switch (c)
        {
            case SW_DEBUG_MODE:
                enclave_mode_cmdline = SW_DEBUG_MODE;
                break;
            case HW_DEBUG_MODE:
                enclave_mode_cmdline = HW_DEBUG_MODE;
                break;
            case HW_RELEASE_MODE:
                enclave_mode_cmdline = HW_RELEASE_MODE;
                break;
            case 'e':
                enclave_image_provided = true;
                strcpy(libsgxlkl, optarg);
                break;
            case 'v':
                version();
                exit(EXIT_SUCCESS);
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'C':
                help_config();
                exit(EXIT_SUCCESS);
            case 'E':
                help_enclave_config();
                exit(EXIT_SUCCESS);
            case 't':
                help_tls();
                exit(EXIT_SUCCESS);
            case 'H':
                host_config_path = optarg;
                break;
            case 'c':
                enclave_config_path = optarg;
                break;
            default:
                sgxlkl_host_fail(
                    "Unexpected command line option: %s\n", argv[optind - 1]);
        }
    }

    sgxlkl_host_verbose(
        SGXLKL_INFO_STRING,
        SGXLKL_VERSION,
        SGXLKL_GIT_COMMIT,
        LKL_VERSION,
        BUILD_INFO);

    argc -= optind;
    argv += optind;
    find_root_disk_file(&argc, &argv, &root_hd);

#ifdef SGXLKL_RELEASE
    (void)(enclave_mode_cmdline);
    if (!enclave_config_path)
        sgxlkl_host_fail("no enclave configuration provided\n");
    enclave_config_from_file(enclave_config_path);
#else
    if (enclave_config_path)
        enclave_config_from_file(enclave_config_path);

    /* Environment variables override enclave config */
    override_enclave_config(argc, argv, root_hd, enclave_mode_cmdline);
#endif

    const sgxlkl_enclave_mode_t enclave_mode = econf->mode;
    sgxlkl_host_verbose_raw(
        enclave_mode == SW_DEBUG_MODE
            ? " [SOFTWARE DEBUG]\n"
            : enclave_mode == HW_DEBUG_MODE
                  ? " [HARDWARE DEBUG]\n"
                  : enclave_mode == HW_RELEASE_MODE ? " [HARDWARE RELEASE]\n"
                                                    : "(Unknown)\n");

    if (enclave_mode == SW_DEBUG_MODE)
        oe_flags = OE_ENCLAVE_FLAG_SIMULATE | OE_ENCLAVE_FLAG_DEBUG;
    else if (enclave_mode == HW_DEBUG_MODE)
        oe_flags = OE_ENCLAVE_FLAG_DEBUG;

    /* Print warnings for ignored options, e.g. for debug options in
     * non-debug mode. */
    check_envs_all(envp);

    if (host_config_path)
        host_config_from_file(host_config_path, root_hd);
    else
        host_config_from_cmdline(root_hd);

    /* Host and guest cannot use virtio in HW mode without bounce buffer,so in
     * hardware mode SWIOTLB is always enabled.
     * SGXLKL_ENABLE_SWIOTLB allows to enable/disable SWIOTLB only in SW mode */
    if (enclave_mode != SW_DEBUG_MODE && !econf->swiotlb)
    {
        sgxlkl_host_fail("SWIOTLB cannot be disabled in hardware mode. Set "
                         "SGXLKL_ENABLE_SWIOTLB=1 to run\n");
    }

    sgxlkl_host_verbose(
        "nproc=%ld ETHREADS=%lu CMDLINE=\"%s\"\n",
        sysconf(_SC_NPROCESSORS_ONLN),
        econf->ethreads,
        econf->kernel_cmd);

    bool have_enclave_config_file = enclave_config_path != NULL;
    set_clock_res(have_enclave_config_file);
    host_state.shared_memory.env = envp;
    set_tls(have_enclave_config_file);
    register_hds(root_hd);
    register_net();

    /* SW mode requires special signal handling, since
     * OE does not support exception handling in SW mode. */
    if (enclave_mode == SW_DEBUG_MODE)
        setup_sw_mode_signal_handlers();

    atexit(sgxlkl_cleanup);

    sgxlkl_host_verbose("get_signed_libsgxlkl_path... ");
    if (!enclave_image_provided)
    {
        get_signed_libsgxlkl_path(libsgxlkl, PATH_MAX);
    }
    sgxlkl_host_verbose_raw("result=%s\n", libsgxlkl);

    parse_cpu_affinity_params(
        host_state.config.thread_affinity,
        &ethreads_cores,
        &ethreads_cores_len);

    sgxlkl_threads = calloc(sizeof(*sgxlkl_threads), econf->ethreads);
    if (sgxlkl_threads == 0)
    {
        sgxlkl_host_fail(
            "Failed to allocate memory for sgxlkl thread info: %s\n",
            strerror(errno));
    }

    host_console_task = calloc(1, sizeof(*host_console_task));
    if (host_console_task == 0)
    {
        sgxlkl_host_fail("Failed to allocate console task mem: %d\n", errno);
    }

    /* Number of Virtio disk task should be the number of disks enabled */
    host_vdisk_task = calloc(sizeof(*host_vdisk_task), host_state.num_disks);
    if (host_vdisk_task == 0)
    {
        sgxlkl_host_fail("Failed to allocate block_dev task mem: %d\n", errno);
    }

    host_netdev_task = calloc(1, sizeof(*host_netdev_task));
    if (host_netdev_task == 0)
    {
        sgxlkl_host_fail("Failed to allocate netdev_task mem : %d\n", errno);
    }

    host_timerdev_task = calloc(1, sizeof(*host_timerdev_task));
    if (host_timerdev_task == 0)
        sgxlkl_host_fail("Failed to allocate timerdev_task mem : %d\n", errno);

    /* Enclave creation */
    sgxlkl_host_verbose("oe_create_enclave...\n");
    _create_enclave(libsgxlkl, oe_flags, &oe_enclave);

    /* Perform host interface initialization */
    sgxlkl_host_interface_initialization();

    /* Total event channel is propotional to the total device count. Currently
     * number of device supported is block, network and console device. Each
     * block disk is treated as a seperate block device and have an event
     * channel associated with it.
     */
    host_state.shared_memory.evt_channel_num =
        host_state.num_disks + HOST_NETWORK_DEV_COUNT + HOST_CONSOLE_DEV_COUNT;

    /* Host & guest device configurations */
    host_dev_config_t* host_dev_cfg = NULL;
    enc_dev_config_t* enc_dev_config = NULL;

    initialize_host_device_configuration(
        econf->swiotlb,
        &host_state.shared_memory,
        &host_dev_cfg,
        &enc_dev_config,
        host_state.shared_memory.evt_channel_num);

    /* Initialize the host dev configuration in host event handler */
    vio_host_initialize_device_cfg(
        host_dev_cfg, host_state.shared_memory.evt_channel_num);

    int dev_index = 0;

    /* Launch block device host tasks */
    for (; dev_index < host_state.num_disks; dev_index++)
    {
        pthread_create(
            &host_vdisk_task[dev_index],
            NULL,
            blkdevice_thread,
            &host_dev_cfg[dev_index]);
        pthread_setname_np(host_vdisk_task[dev_index], "HOST_BLKDEVICE");
    }

    /* Pass the enclave dev configuration in enclave event handler */
    host_state.shared_memory.enc_dev_config = enc_dev_config;

    /* Launch network device host task */
    if (host_state.net_fd != 0)
    {
        int ret = netdev_init(&host_state);
        if (ret < 0)
        {
            sgxlkl_host_fail("Network device initialization failed\n");
        }
        else
        {
            pthread_create(
                host_netdev_task,
                NULL,
                netdev_task,
                &host_dev_cfg[dev_index++]);
            pthread_setname_np(*host_netdev_task, "HOST_NETDEV");
        }
    }

    /* Initialize the virtio console backend driver configuration */
    virtio_console_init(&host_state, &host_dev_cfg[dev_index++]);

    /* Create host console device task */
    pthread_create(host_console_task, NULL, console_task, NULL);
    pthread_setname_np(*host_console_task, "HOST_CONSOLE_DEVICE");

    int ret = timerdev_init(&host_state.shared_memory);
    if (ret < 0)
        sgxlkl_host_fail("Timer device initialization failed\n");
    else
    {
        pthread_create(
            host_timerdev_task,
            NULL,
            timerdev_task,
            host_state.shared_memory.timer_dev_mem);
        pthread_setname_np(*host_timerdev_task, "HOST_TIMER_DEVICE");
    }

#ifdef DEBUG
    /* Need base address for GDB to work */
    _oe_enclave_partial* oe_enclave_content = (_oe_enclave_partial*)oe_enclave;
    void* base_addr = (void*)oe_enclave_content->addr;
    __gdb_hook_starter_ready(base_addr, econf->mode, libsgxlkl);
#endif

    ethread_args_t ethreads_args[econf->ethreads];

    for (int i = 0; i < econf->ethreads; i++)
    {
        pthread_attr_init(&eattr);
        if (ethreads_cores_len)
        {
            CPU_ZERO(&set);
            CPU_SET(ethreads_cores[i % ethreads_cores_len], &set);
            pthread_attr_setaffinity_np(&eattr, sizeof(set), &set);
        }

        ethreads_args[i].ethread_id = i;
        ethreads_args[i].shm = &host_state.shared_memory;
        ethreads_args[i].oe_enclave = oe_enclave;

        /* First ethread will pass the enclave configuration and settings */
        if (i == 0)
        {
            pthread_create(
                &sgxlkl_threads[i],
                &eattr,
                (void*)enclave_init,
                &ethreads_args[i]);
        }
        else
        {
            pthread_create(
                &sgxlkl_threads[i],
                &eattr,
                (void*)ethread_init,
                &ethreads_args[i]);
        }

        pthread_setname_np(sgxlkl_threads[i], "ENCLAVE");
    }

    long exit_status = 0;

    for (int i = 0; i < econf->ethreads; i++)
    {
        pthread_join(sgxlkl_threads[i], &return_value);
        if (i == 0)
        {
            exit_status = (long)return_value;
        }
    }
    sgxlkl_host_verbose_raw("\n");

    if (oe_enclave)
    {
        sgxlkl_host_verbose("oe_terminate_enclave... ");
        oe_terminate_enclave(oe_enclave);
        sgxlkl_host_verbose_raw("done\n");
    }

    sgxlkl_host_verbose("SGX-LKL-OE exit: exit_status=%i\n", exit_status);
    return exit_status;
}
