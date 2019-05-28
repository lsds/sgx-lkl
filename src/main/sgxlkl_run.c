/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * Copyright 2016, 2017 TU Dresden (under SCONE source code license)
 */

#define _GNU_SOURCE
#define WANT_REAL_ARCH_SYSCALLS
#include <link.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <elf.h>
#include <signal.h>
#include <assert.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <getopt.h>

#include "enclave_mem.h"
#include "load_elf.h"
#include "mpmc_queue.h"
#include "sgx_enclave_config.h"
#include "sgxlkl_config.h"
#include "sgxlkl_util.h"

#include "lkl/linux/virtio_net.h"

#ifdef SGXLKL_HW
#include "aesm.h"
#include "attest_ias.h"
#include "attest.h"
#include "enclave_signal.h"
#endif /* SGXLKL_HW */

#ifndef RTLD_DEEPBIND
#define RTLD_DEEPBIND 0
#endif
#ifndef str
#define str(X) #X
#endif
#define __merge(a, b) a(b)
#define __stringify(X) __merge(str, X)

extern char __sgxlklrun_text_segment_start;

#if DEBUG

#include "sgxlkl_host_debug.h"

#define MAX_SYSCALL_NUMBER 512
#define MAX_EXIT_REASON_NUMBER 16

static unsigned long _enclave_exit_stats[MAX_EXIT_REASON_NUMBER] = {0};
static const char* const _enclave_exit_reasons[] = {
    "TERMINATE",
    "SYSCALL",
    "ERROR",
    "SLEEP",
    "CPUID",
    "DORESUME",
    "REPORT"
};

static unsigned long _host_syscall_stats[MAX_SYSCALL_NUMBER];
static int _sigint_handling = 0;

extern unsigned long hw_exceptions;
#endif /* DEBUG */

// One first empty block for bootloaders, and offset in second block
#define EXT4_MAGIC_OFFSET (1024 + 0x38)

#define MAX_KEY_FILE_SIZE_KB 8192
#define MAX_HASH_DIGITS 512
#define MAX_HASHOFFSET_DIGITS 16

// Keep track of enclave disk image files so we can flush changes to them
// on exit.
static struct enclave_disk_config *_encl_disks = 0;
static size_t _encl_disk_cnt = 0;

// Is set to 1 when terminating the enclave to prevent concurrent threads from
// trying to reenter.
static int __state_exiting = 0;

static pthread_spinlock_t _stdout_print_lock = {0};
static pthread_spinlock_t _stderr_print_lock = {0};

static size_t backoff_maxpause;
static size_t backoff_factor;

#ifdef SGXLKL_HW
void get_quote(sgx_report_t *report, sgx_quote_t *quote, uint32_t quote_size);
attestation_verification_report_t *get_attestation_report(sgx_quote_t *quote, size_t quote_size);

extern void eresume(uint64_t tcs_id);

char* init_sgx();
int   get_tcs_num();
void  enter_enclave(int tcs_id, uint64_t call_id, void* arg, uint64_t* ret);
uint64_t create_enclave_mem(char* p, int base_zero, void *base_zero_max);
void     enclave_update_heap(void *p, size_t new_heap, char* key_path);

typedef struct {
    int   tcs_id;
    int   call_id;
    void* args;
} args_t;

__thread int my_tcs_id;

static struct attestation_config _attn_config;
static int _aemsd_fd;
#else /* SGXLKL_HW */
/* By default non-PIE Linux binaries expect their text segment to be mapped to
 * address 0x400000. However, we use the first few pages of the enclave heap
 * for the mmap bitmap containing metadata about mapped/unmapped pages.
 * Therefore, we map the enclave at a lower address to ensure that 0x400000 is
 * available when the executable is mapped.
 */
#define SIM_NON_PIE_ENCL_MMAP_OFFSET 0x200000

/* Conditional variable to indicate exit, only used in simulation mode.
   exit_mtx protects the cv. exit_code is set to the exit code set by the
   application.
*/
pthread_cond_t sim_exit_cv;
pthread_mutex_t sim_exit_mtx;
int sim_exit_code;
#endif /* SGXLKL_HW */

#define VERSION "1.0.0"
#ifdef DEBUG
#define DEBUG_INFO " DEBUG"
#else
#define DEBUG_INFO ""
#endif /* DEBUG */
#ifdef SGXLKL_HW
#define SGX_MODE "Hardware Mode"
#else
#define SGX_MODE "Simulation Mode"
#endif /* SGXLKL_HW */

static void version() {
    printf("SGX-LKL version %s %s%s\n", VERSION, SGX_MODE, DEBUG_INFO);
}

static void usage(char* prog) {
    printf("Usage: %s [--config=path/to/config]  [--app=path/to/appconfig] path/to/encl/file/system path/to/executable <args>\n", prog);
    printf("  path/to/config: Optional: Path to JSON configuration file. If file system image is provided via configuration file it must not be provided on the command line (see below).\n");
    printf("  path/to/appconfig: Optional: Path to JSON application configuration file. Can be used to provide application configuration (executable path, arguments, environment variables). Not available in release mode.\n");
    printf("  path/to/encl/file/system: Path to the ext4 enclave file system image.\n");
    printf("  path/to/executable: Path to executable on enclave file system.\n");
    printf("  <args>: Arguments for executable.\n");
    printf("\n%s --version to print version information.\n", prog);
    printf("%s --help to print this help.\n", prog);
    printf("%s --help-tls to print help on how to enable thread-local storage support in hardware mode.\n", prog);
}

static void help(char* prog) {
    usage(prog);
    printf("\n\nSGX-LKL configuration via environment variables:\n");
    printf("## General ##\n");
    printf("SGXLKL_CMDLINE: Linux kernel command line.\n");
    printf("SGXLKL_SIGPIPE: Set to 1 to enable delivery of SIGPIPE.\n");
    printf("SGXLKL_NON_PIE: Set to 1 when running applications not compiled as position-independent. In this case the size of the enclave is limited to the available space at the beginning of the address space.\n");
    printf("\n## Scheduling & Host system calls ##\n");
    printf("SGXLKL_ESLEEP: Sleep timeout in the scheduler (in ns).\n");
    printf("SGXLKL_ESPINS: Number of spins inside scheduler before sleeping begins.\n");
    printf("SGXLKL_ETHREADS: Number of enclave threads.\n");
    printf("SGXLKL_STHREADS: Number of system call threads outside the enclave.\n");
    printf("SGXLKL_MAX_USER_THREADS: Max. number of user-level thread inside the enclave.\n");
    printf("SGXLKL_REAL_TIME_PRIO: Set to 1 to use realtime priority for enclave threads.\n");
    printf("SGXLKL_SSPINS: Number of spins inside host syscall threads before sleeping begins.\n");
    printf("SGXLKL_SSLEEP: Sleep timeout in the syscall threads (in ns).\n");
    printf("SGXLKL_GETTIME_VDSO: Set to 1 to use the host kernel vdso mechanism to handle clock_gettime calls (Default: 1).\n");
    printf("SGXLKL_ETHREADS_AFFINITY: Specifies the CPU core affinity for enclave threads as a comma-separated list of cores to use, e.g. \"0-2,4\".\n");
    printf("SGXLKL_STHREADS_AFFINITY: Specifies the CPU core affinity for system call threads as a comma-separated list of cores to use, e.g. \"0-2,4\".\n");
    printf("\n## Network ##\n");
    printf("SGXLKL_TAP: Tap for LKL to use as a network interface.\n");
    printf("SGXLKL_TAP_OFFLOAD: Set to 1 to enable partial checksum support, TSOv4, TSOv6, and mergeable receive buffers for the TAP interface.\n");
    printf("SGXLKL_TAP_MTU: Sets MTU on the SGX-LKL side of the TAP interface. Must be set on the host separately (e.g. ifconfig sgxlkl_tap0 mtu 9000).\n");
    printf("SGXLKL_IP4: IPv4 address to assign to LKL (Default: %s).\n", DEFAULT_SGXLKL_IP4);
    printf("SGXLKL_GW4: IPv4 gateway to assign to LKL (Default: %s).\n", DEFAULT_SGXLKL_GW4);
    printf("SGXLKL_MASK4: CIDR mask for LKL to use (Default: %d).\n", DEFAULT_SGXLKL_MASK4);
    printf("SGXLKL_HOSTNAME: Host name for LKL to use (Default: %s).\n", DEFAULT_SGXLKL_HOSTNAME);
    //printf("SGXLKL_HOSTNET: Use host network directly without going through the in-enclave network stack.\n");
    printf("SGXLKL_WG_IP: IPv4 address to assign to Wireguard interface (Default: %s).\n", DEFAULT_SGXLKL_WG_IP);
    printf("SGXLKL_WG_PORT: Port to use on eth0 interface for the Wireguard endpoint (Default: %d).\n", DEFAULT_SGXLKL_WG_PORT);
    printf("SGXLKL_WG_KEY: Private Wireguard key. Will be ignored in release mode in which a new key pair is generated inside the enclave on startup.\n");
    printf("SGXLKL_WG_PEERS: Comma-separated list of Wireguard peers in the format \"key1:allowedips1:endpointhost1:port1, key2:allowedips2:...\".\n");
    printf("\n## Disk ##\n");
    printf("SGXLKL_HD_VERITY: Root hash or file path to root hash for the root file system image (Debug only).\n");
    printf("SGXLKL_HD_VERITY_OFFSET: Offset or file path to offset of the dm-verity merkle tree on the root file system image (Debug only). If omitted and <path/to/diskimage>.hashoffset exists, this offset will be used if possible.\n");
    printf("SGXLKL_HD_KEY: Encryption key as passphrase or file path to a key file for the root file system image (Debug only).\n");
    printf("SGXLKL_HD_RO: Set to 1 to mount the root file system as read-only.\n");
    printf("SGXLKL_HDS: Secondary file system images. Comma-separated list of the format: disk1path:disk1mntpoint:disk1mode,disk2path:disk2mntpoint:disk2mode,[...].\n");
    printf("SGXLKL_HD_MMAP: Set to 1 to use file-backed mmap to read from and write to disks instead of using host read/write system calls.\n");
    printf("\n## Memory ##\n");
    printf("SGXLKL_HEAP: Total heap size (in bytes) available in the enclave. This includes memory used by the kernel.\n");
    printf("SGXLKL_STACK_SIZE: Stack size of in-enclave user-level threads.\n");
    printf("SGXLKL_MMAP_FILES: Set to \"Private\" to allow mmaping files with private copy-on-write mapping ('MAP_PRIVATE'). Set to \"Shared\" to allow mmaping files with 'MAP_SHARED'. These files will be mapped as if 'MAP_PRIVATE' has been used instead. Default: No File mapping supported.\n");
    printf("SGXLKL_SHMEM_FILE: Name of the file to be used for shared memory between the enclave and the outside.\n");
    printf("SGXLKL_SHMEM_SIZE: Size of the file to be used for shared memory between the enclave and the outside.\n");
    printf("\n## Attestation ##\n");
    printf("SGXLKL_IAS_SPID: Specifies the Service Provider ID (SPID) required for communication with the Intel Attestation Service (IAS).\n");
    printf("SGXLKL_IAS_QUOTE_TYPE: Specifies the quote type: '0' for unlinkable quotes (default), '1' for linkable quotes.\n");
    printf("SGXLKL_IAS_KEY_FILE: Path to the private key file.\n");
    printf("SGXLKL_IAS_CERT: Path to the IAS certificate file.\n");
    printf("SGXLKL_IAS_SERVER: IAS server to use (Default: %s).\n", DEFAULT_SGXLKL_IAS_SERVER);
    printf("\n## Remote control ##\n");
    printf("SGXLKL_REMOTE_ATTEST_PORT: Port to use on public interface for attestation server (Default: %d).\n", DEFAULT_SGXLKL_REMOTE_ATTEST_PORT);
    printf("SGXLKL_REMOTE_CMD_PORT: Port to use on Wireguard interface for remote control server (Default: %d).\n", DEFAULT_SGXLKL_REMOTE_CMD_PORT);
    printf("SGXLKL_REMOTE_CMD_ETH0: Set to 1 to expose server on eth0 interface instead. If specified no separate attestation server is created. Will be ignored in release mode.\n");
    printf("SGXLKL_REMOTE_CONFIG: Set to 1 to ignore application and application arguments specified via command line and wait for application configuration to be provided via remote control server (Default: 0, always 1 in release mode).\n");
    printf("\n## Debugging ##\n");
    printf("SGXLKL_VERBOSE: Print information about the SGX-LKL start up process as well as kernel messages.\n");
    printf("SGXLKL_TRACE_MMAP: Print detailed information about in-enclave mmap/munmap operations.\n");
    printf("SGXLKL_TRACE_THREAD: Print detailed information about in-enclave user level thread scheduling.\n");
    printf("SGXLKL_TRACE_SYSCALL: Print detailed information about all system calls.\n");
    printf("SGXLKL_TRACE_LKL_SYSCALL: Print detailed information about in-enclave system calls handled by LKL.\n");
    printf("SGXLKL_TRACE_INTERNAL_SYSCALL: Print detailed information about in-enclave system calls not handled by LKL (in particular mmap/mremap/munmap and futex).\n");
    printf("SGXLKL_TRACE_HOST_SYSCALL: Print detailed information about host system calls.\n");
    printf("SGXLKL_PRINT_HOST_SYSCALL_STATS: Print statistics on the number of host system calls and enclave exits.\n");
    printf("SGXLKL_PRINT_APP_RUNTIME: Measure and print total runtime of the application itself excluding the enclave and SGX-LKL startup and shutdown time.\n");
}

static void help_tls() {
    printf("Support for Thread-Local Storage (TLS) in hardware mode\n"
           "\n"
           "On x86-64 platforms thread-local storage for applications and their initially\n"
           "available dependencies is expected to be accessible via fixed offsets from the\n"
           "current value of the FS segment base. Whenever a switch from one thread to\n"
           "another occurs, the FS segment base has to be changed accordingly. Typically\n"
           "this is done by the privileged kernel. However, with SGX the FS segment base is\n"
           "explicitly set when entering the enclave (OFSBASE field of the TCS page) and\n"
           "reset when leaving the enclave. SGX-LKL schedules application threads within\n"
           "the enclaves without leaving the enclave. It therefore needs to be able to set\n"
           "the FS segment base on context switches. This can be done with the WRFSBASE\n"
           "instruction that allows to set the FS segment base at any privilege level.\n"
           "However, this is only possible if the control register bit CR4.FSGSBASE is set\n"
           "to 1. On current Linux kernels this bit is not set as the kernel is not able to\n"
           "handle FS segment base changes by userspace applications. Note that changes to\n"
           "the segment from within an enclave are transparent to the kernel.\n"
           "\n"
           "In order to allow SGX-LKL to set the segment base from within the enclave, the\n"
           "CR4.FSGSBASE bit has to be set to 1. SGX-LKL provides a kernel module to do\n"
           "this. In order to build the module and set the CR4.FSGSBASE to 1 run the\n"
           "following:\n"
           "\n"
           "  cd tools/kmod-set-fsgsbase; make set-cr4-fsgsbase\n"
           "\n"
           "In order to set it back to 0, run:\n"
           "\n"
           "  cd tools/kmod-set-fsgsbase; make unset-cr4-fsgsbase\n"
           "\n"
           "WARNING: While using WRFSBASE within the enclave should have no impact on the\n"
           "host OS, allowing other userspace applications to use it can impact the\n"
           "stability of those applications and potentially the kernel itself. Enabling\n"
           "FSGSBASE should be done with care.\n"
           "\n");
}

__attribute__((noinline)) unsigned backoffslow(unsigned n) {
    const size_t maxbackoff = 800;
    struct timespec ts = {0, 0};
    n = n - backoff_maxpause;
    n = n <= maxbackoff ? n : maxbackoff;
    ts.tv_nsec = backoff_factor*n;
    nanosleep(&ts, NULL);
    return backoff_maxpause + n*2;
}

static inline unsigned backoff(unsigned n) {
    if (n <= backoff_maxpause) {
        __asm__ __volatile__( "pause" : : : "memory" );
        return n + 1;
    } else {
        return backoffslow(n);
    }
}

static inline void do_syscall(syscall_t *sc) {
    unsigned long ret;
    unsigned long n = sc->syscallno;
    register long r10 __asm__("r10") = sc->arg4;
    register long r8 __asm__("r8") = sc->arg5;
    register long r9 __asm__("r9") = sc->arg6;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(sc->arg1), "S"(sc->arg2),
            "d"(sc->arg3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    sc->ret_val = ret;
}

void *host_syscall_thread(void *v) {
    enclave_config_t *conf = v;
    volatile syscall_t *scall = conf->syscallpage;
    pthread_spinlock_t* curr_print_lock = NULL;
    size_t i;
    unsigned s;
    union {void *ptr; size_t i;} u;
    u.ptr = MAP_FAILED;
    while (1) {
        for (s = 0; !mpmc_dequeue(&conf->syscallq, &u.ptr);) {s = backoff(s);}
        i = u.i;

#ifdef DEBUG
        long syscallno = scall[i].syscallno;
        __sync_fetch_and_add(&_host_syscall_stats[syscallno], 1);
#endif /* DEBUG */

        /* Acquire ticket lock if the system call writes to stdout or stderr to prevent mangling of concurrent writes */
        if (scall[i].syscallno == SYS_write || scall[i].syscallno == SYS_writev) {
            int fd = (int) scall[i].arg1;
            if (fd == STDOUT_FILENO) {
                pthread_spin_lock(&_stdout_print_lock);
                curr_print_lock = &_stdout_print_lock;
            } else if (fd == STDERR_FILENO) {
                pthread_spin_lock(&_stderr_print_lock);
                curr_print_lock = &_stderr_print_lock;
            }
        }

        if (scall[i].syscallno == SYS_clock_gettime) {
            scall[i].ret_val = clock_gettime(scall[i].arg1, (struct timespec *)scall[i].arg2);
            if (scall[i].ret_val != 0) {
                scall[i].ret_val = -errno;
            }
        } else {
            do_syscall((syscall_t*)&scall[i]);
        }

        /* Release ticket lock if previously acquired */
        if (curr_print_lock) {
            pthread_spin_unlock(curr_print_lock);
            curr_print_lock = NULL;
        }

#ifdef DEBUG
        if (sgxlkl_config_bool(SGXLKL_TRACE_SYSCALL) || sgxlkl_config_bool(SGXLKL_TRACE_HOST_SYSCALL)) {
            pthread_spin_lock(&_stdout_print_lock);
            log_host_syscall(syscallno, scall[i].ret_val, scall[i].arg1, scall[i].arg2, scall[i].arg3, scall[i].arg4, scall[i].arg5, scall[i].arg6);
            pthread_spin_unlock(&_stdout_print_lock);
        }
#endif /* DEBUG */

        if (scall[i].status == 1) {
            /* This was submitted by the scheduler or a pinned thread, no need to push anything to queue */
            __atomic_store_n(&scall[i].status, 2, __ATOMIC_RELEASE);
        } else {
            for (s = 0; !mpmc_enqueue(&conf->returnq, u.ptr);) {s = backoff(s);}
        }
    }

    return NULL;
}

static void prepare_verity(struct enclave_disk_config *disk, char *disk_path, char *verity_file_or_roothash, char *verity_file_or_hashoffset) {
    if (!verity_file_or_roothash) {
        disk->roothash = NULL;
        disk->roothash_offset = 0;
        return;
    }

    if (access(verity_file_or_roothash, R_OK) != -1) {
        FILE *hf;
        char hash[MAX_HASH_DIGITS + 2];

        if (!(hf = fopen(verity_file_or_roothash, "r")))
            sgxlkl_fail("Failed to open root hash file %s.\n", verity_file_or_roothash);

        if (!fgets(hash, MAX_HASH_DIGITS + 2, hf))
            sgxlkl_fail("Failed to read root hash from file %s.\n", verity_file_or_roothash);

        /* Remove possible new line */
        char *nl = strchr(hash, '\n');
        if (nl) *nl = 0;

        size_t hash_len = strlen(hash);
        if (hash_len > MAX_HASH_DIGITS)
            sgxlkl_fail("Root hash read from file %s too long! Maximum length: %d\n", verity_file_or_roothash, MAX_HASH_DIGITS);

        disk->roothash = (char*) malloc(hash_len + 1);
        strncpy(disk->roothash, hash, hash_len);
        disk->roothash[hash_len] = 0;

        fclose(hf);
    } else
        disk->roothash = verity_file_or_roothash;


    char *hashoffset_path;
    if (!verity_file_or_hashoffset) {
        size_t hashoffset_path_len = strlen(disk_path) + strlen(".hashoffset") + 1;
        hashoffset_path = (char*) malloc(hashoffset_path_len);
        snprintf(hashoffset_path, hashoffset_path_len, "%s%s", disk_path, ".hashoffset");
    } else {
        hashoffset_path = verity_file_or_hashoffset;
    }

    char *hashoffset_str;
    if (access(hashoffset_path, R_OK) != -1) {
        FILE *hf;
        char hashoffset_buf[MAX_HASHOFFSET_DIGITS];

        if (!(hf = fopen(hashoffset_path, "r")))
            sgxlkl_fail("Failed to open hash offset file %s.\n", hashoffset_path);

        if (!fgets(hashoffset_buf, MAX_HASHOFFSET_DIGITS, hf))
            sgxlkl_fail("Failed to read hash offset from file %s.\n", hashoffset_path);

        fclose(hf);

        hashoffset_str = hashoffset_buf;
    } else if (verity_file_or_hashoffset) {
        hashoffset_str = verity_file_or_hashoffset;
    } else
        sgxlkl_fail("A hash offset must be set via SGXLKL_HD_VERITY_OFFSET when SGXLKL_HD_VERITY is used.\n");

    errno = 0;
    disk->roothash_offset = strtoll(hashoffset_str, NULL, 10);
    if (errno == EINVAL || errno == ERANGE)
        sgxlkl_fail("Failed to parse hash offset!\n");

    if (hashoffset_path != verity_file_or_hashoffset)
        free(hashoffset_path);
}

static int is_disk_encrypted(int fd) {
    unsigned char magic[2] = {0};
    ssize_t read_bytes = pread(fd, magic, 2, EXT4_MAGIC_OFFSET);
    if (read_bytes != 2) {
        perror("pread(disk,2,EXT4_MAGIC_OFFSET)");
        return 0;
    }
    return !(magic[0] == 0x53 && magic[1] == 0xEF);
}

static void register_hd(enclave_config_t* encl, char* path, char* mnt, int readonly, char *keyfile_or_passphrase, char *verity_file_or_roothash, char *verity_file_or_hashoffset) {
    size_t idx = encl->num_disks;

    if (strlen(mnt) > SGXLKL_DISK_MNT_MAX_PATH_LEN)
        sgxlkl_fail("Mount path for disk %lu too long (maximum length is %d): \"%s\"\n", idx, SGXLKL_DISK_MNT_MAX_PATH_LEN, mnt);

    int fd = open(path, readonly ? O_RDONLY : O_RDWR);
    if (fd == -1) sgxlkl_fail("Unable to open disk file %s for %s access: %s\n", path, readonly ? "read" : "read/write", strerror(errno));

    struct stat disk_stat;
    fstat(fd, &disk_stat);
    char * disk_mmap = mmap(NULL, disk_stat.st_size, PROT_READ | (readonly ? 0 : PROT_WRITE), MAP_SHARED, fd, 0);
    if (disk_mmap == MAP_FAILED)
        sgxlkl_fail("Could not map memory for disk image: %s\n", strerror(errno));

    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) sgxlkl_fail("fcntl(disk_fd, F_GETFL)");

    int res = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (res == -1) sgxlkl_fail("fcntl(disk_fd, F_SETFL)");

    struct enclave_disk_config *disk = &encl->disks[idx];
    disk->fd = fd;
    disk->ro = readonly;
    disk->capacity = disk_stat.st_size;
    disk->mmap = disk_mmap;
    strncpy(disk->mnt, mnt, SGXLKL_DISK_MNT_MAX_PATH_LEN);
    disk->mnt[SGXLKL_DISK_MNT_MAX_PATH_LEN] = '\0';
    disk->enc = is_disk_encrypted(fd);
#ifndef SGXLKL_RELEASE
    if (disk->enc && !sgxlkl_config_bool(SGXLKL_REMOTE_CONFIG)) {
#else
    // In release mode the key will be provided remotely.
    if (0) {
#endif
        if (!keyfile_or_passphrase)
            sgxlkl_fail("No passphrase or key file provided via SGXLKL_HD_KEY for encrypted disk %s.\n", path);

        // Currently we have a single parameter for passphrases and keyfiles. Determine which one it is.
        if (access(keyfile_or_passphrase, R_OK) != -1) {
            FILE *kf;

            if (!(kf = fopen(keyfile_or_passphrase, "rb")))
                sgxlkl_fail("Failed to open keyfile %s.\n", keyfile_or_passphrase);

            fseek(kf, 0, SEEK_END);
            disk->key_len = ftell(kf);
            if (disk->key_len > MAX_KEY_FILE_SIZE_KB * 1024) {
                sgxlkl_warn("Provided key file is larger than maximum supported key file size (%dkB). Only the first %dkB will be used.\n", MAX_KEY_FILE_SIZE_KB, MAX_KEY_FILE_SIZE_KB);
                disk->key_len = MAX_KEY_FILE_SIZE_KB * 1024;
            }
            rewind(kf);

            disk->key = (char *) malloc((disk->key_len));
            if (!fread(disk->key, disk->key_len, 1, kf))
                sgxlkl_fail("Failed to read keyfile %s.\n", keyfile_or_passphrase);

            fclose(kf);
        } else {
            disk->key_len = strlen(keyfile_or_passphrase);
            disk->key = (char *) malloc(disk->key_len);
            memcpy(disk->key, keyfile_or_passphrase, disk->key_len);
        }
    }

#ifndef SGXLKL_RELEASE
    prepare_verity(disk, path, verity_file_or_roothash, verity_file_or_hashoffset);
#endif

    ++encl->num_disks;
}

static void register_hds(enclave_config_t *encl, char *root_hd) {
    // Count disks to register
    size_t num_disks = 1; // Root disk
    char *hds_str = sgxlkl_config_str(SGXLKL_HDS);
    if (hds_str[0]) {
        num_disks++;
        for (int i = 0; hds_str[i]; i++) {
            if (hds_str[i] == ',') num_disks++;
        }
    }

    // Allocate space for encave disk configurations
    encl->disks = (struct enclave_disk_config*) malloc(sizeof(struct enclave_disk_config) * num_disks);
    // Initialize encl->num_disks, will be adjusted by register_hd
    encl->num_disks = 0;
    // Register root disk
    register_hd(encl, root_hd, "/", sgxlkl_config_bool(SGXLKL_HD_RO), sgxlkl_config_str(SGXLKL_HD_KEY),
                sgxlkl_config_str(SGXLKL_HD_VERITY), sgxlkl_config_str(SGXLKL_HD_VERITY_OFFSET));
    // Register secondary disks
    while (*hds_str) {
        char *hd_path = hds_str;
        char *hd_mnt = strchrnul(hd_path, ':');
        *hd_mnt = '\0';
        hd_mnt++;
        char *hd_mnt_end = strchrnul(hd_mnt, ':');
        *hd_mnt_end = '\0';
        int hd_ro = hd_mnt_end[1] == '1' ? 1 : 0;
        register_hd(encl, hd_path, hd_mnt, hd_ro, NULL, NULL, NULL);

        hds_str = strchrnul(hd_mnt_end + 1, ',');
        while(*hds_str == ' ' || *hds_str == ',') hds_str++;
    }

    // Keep track of disks in order to close fds properly at exit
    _encl_disks = encl->disks;
    _encl_disk_cnt = encl->num_disks;
}

static void *register_shm(char* path, size_t len) {
    if (path == NULL || strlen(path) == 0)
        exit(EXIT_FAILURE);

    int fd = shm_open(path, O_TRUNC | O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (fd == -1) sgxlkl_fail("Unable to access shared memory %s (%s)\n", path, strerror(errno));

    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) sgxlkl_fail("fcntl(shmem_fd, F_GETFL)");

    int res = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (res == -1) sgxlkl_fail("fcntl(shmem_fd, F_SETFL)");

    if (len <= 0) sgxlkl_fail("Invalid memory size length %zu\n", len);

    if(ftruncate(fd, len) == -1) sgxlkl_fail("ftruncate: %s\n", strerror(errno));

    void *addr;
    if ((addr = mmap(0, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
        sgxlkl_fail("Could not mmap shared memory region: %s\n", strerror(errno));

    close(fd);
    return addr;
}

static void register_net(enclave_config_t* encl, const char* tapstr, const char* ip4str,
        int mask4, const char* gw4str, const char* hostname) {
    // Set hostname
    strncpy(encl->hostname, hostname, sizeof(encl->hostname));
    encl->hostname[sizeof(encl->hostname) - 1] = '\0';

    if (encl->net_fd != 0) sgxlkl_fail("Multiple network interfaces not supported yet\n");

    // Open tap device FD
    if (tapstr == NULL || strlen(tapstr) == 0) {
        if (sgxlkl_config_bool(SGXLKL_VERBOSE))
            printf("[    SGX-LKL   ] No tap device specified, networking will not be available.\n");
        return;
    }
    struct ifreq ifr;
    strncpy(ifr.ifr_name, tapstr, IFNAMSIZ);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    int vnet_hdr_sz = 0;
    if (sgxlkl_config_bool(SGXLKL_TAP_OFFLOAD)) {
        ifr.ifr_flags |= IFF_VNET_HDR;
        vnet_hdr_sz = sizeof(struct lkl_virtio_net_hdr_v1);
    }

    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd == -1) sgxlkl_fail("TUN network device unavailable, open(\"/dev/net/tun\") failed");

    if (ioctl(fd, TUNSETIFF, &ifr) == -1)
        sgxlkl_fail("Tap device %s unavailable, ioctl(\"/dev/net/tun\"), TUNSETIFF) failed: %s\n", tapstr, strerror(errno));

    if (vnet_hdr_sz && ioctl(fd, TUNSETVNETHDRSZ, &vnet_hdr_sz) != 0)
        sgxlkl_fail("Failed to TUNSETVNETHDRSZ: /dev/net/tun: %s\n", strerror(errno));

    int offload_flags = 0;
    if (sgxlkl_config_bool(SGXLKL_TAP_OFFLOAD)) {
        offload_flags = TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_CSUM;
    }

    if (ioctl(fd, TUNSETOFFLOAD, offload_flags) != 0)
        sgxlkl_fail("Failed to TUNSETOFFLOAD: /dev/net/tun: %s\n", strerror(errno));

    encl->tap_offload = sgxlkl_config_bool(SGXLKL_TAP_OFFLOAD);
    encl->tap_mtu = (int) sgxlkl_config_uint64(SGXLKL_TAP_MTU);

    encl->hostnet = sgxlkl_config_bool(SGXLKL_HOSTNET);

    struct in_addr ip4 = { 0 };
    if (inet_pton(AF_INET, ip4str, &ip4) != 1)
        sgxlkl_fail("Invalid IPv4 address %s\n", ip4str);

    struct in_addr gw4 = { 0 };
    if (gw4str != NULL && strlen(gw4str) > 0 &&
            inet_pton(AF_INET, gw4str, &gw4) != 1) {
        sgxlkl_fail("Invalid IPv4 gateway %s\n", ip4str);
    }

    if (mask4 < 1 || mask4 > 32) sgxlkl_fail("Invalid IPv4 mask %d\n", mask4);

    encl->net_fd = fd;
    encl->net_ip4 = ip4;
    encl->net_gw4 = gw4;
    encl->net_mask4 = mask4;
}

static void register_queues(enclave_config_t* encl) {
    int mmapflags = MAP_PRIVATE|MAP_ANONYMOUS;

    // Maximum number of syscall and return queue elements is user-level
    // threads + ethreads.
    size_t sqs = encl->maxsyscalls * sizeof(*encl->syscallq.buffer);
    size_t rqs = encl->maxsyscalls * sizeof(*encl->returnq.buffer);
    // The mpmc implementation requires the buffer size to be a power of two.
    sqs = next_pow2(sqs);
    rqs = next_pow2(rqs);

    void *rq = mmap(0, rqs, PROT_READ|PROT_WRITE, mmapflags, -1, 0);
    if (rq == MAP_FAILED) sgxlkl_fail("Could not allocate memory for return queue: %s\n", strerror(errno));
    void *sq = mmap(0, sqs, PROT_READ|PROT_WRITE, mmapflags, -1, 0);
    if (rq == MAP_FAILED) sgxlkl_fail("Could not allocate memory for syscall queue: %s\n", strerror(errno));
    encl->syscallpage = calloc(sizeof(syscall_t), encl->maxsyscalls);
    if (encl->syscallpage == NULL) sgxlkl_fail("Could not allocate memory for syscall pages: %s\n", strerror(errno));

    newmpmcq(&encl->syscallq, sqs, sq);
    newmpmcq(&encl->returnq, rqs, rq);
}

#define MIN(a,b) (((a)<(b))?(a):(b))

void set_sysconf_params(enclave_config_t *conf, long no_ethreads) {
    conf->sysconf_nproc_conf = no_ethreads;
    conf->sysconf_nproc_onln = no_ethreads;
}

static void *find_vvar_base(void) {
    FILE *maps;
    char mapping[128];
    void *vvar_base = 0;

    if (!(maps = fopen("/proc/self/maps", "r")))
        return NULL;

    int found = 0;
    while (!found && fgets(mapping, sizeof(mapping), maps)) {
        int name_idx = -1;
        if (sscanf(mapping, "%p-%*p r-%*cp %*x %*x:%*x %*u %n",
               &vvar_base, &name_idx) != 1) {
            continue;
        }

        if (name_idx >= 0 && !strncmp(&mapping[name_idx], "[vvar]", sizeof("[vvar]") - 1))
            found = 1;
    }

    fclose(maps);
    return found ? vvar_base : NULL;
}

void set_vdso(enclave_config_t* conf) {
    conf->vvar = 0;
    if (!sgxlkl_config_bool(SGXLKL_GETTIME_VDSO)) return;

    // Try to locate vvar pages
    if (!(conf->vvar = find_vvar_base()))
        fprintf(stderr, "[    SGX-LKL   ] Warning: Could not locate vvar region. vDSO will not be used.\n");
}

/* Sets up shared memory with the outside */
void set_shared_mem(enclave_config_t *conf) {
    char *shm_file = sgxlkl_config_str(SGXLKL_SHMEM_FILE);
    size_t shm_len = sgxlkl_config_uint64(SGXLKL_SHMEM_SIZE);
    if (shm_file == 0 || strlen(shm_file) <= 0 || shm_len <= 0)
        return;

    char shm_file_enc_to_out[strlen(shm_file)+4];
    char shm_file_out_to_enc[strlen(shm_file)+4];

    snprintf(shm_file_enc_to_out, strlen(shm_file)+4, "%s-eo", shm_file);
    snprintf(shm_file_out_to_enc, strlen(shm_file)+4, "%s-oe", shm_file);

    conf->shm_common = register_shm(shm_file, shm_len);
    conf->shm_enc_to_out = register_shm(shm_file_enc_to_out, shm_len);
    conf->shm_out_to_enc = register_shm(shm_file_out_to_enc, shm_len);
}

static int rdfsbase_caused_sigill = 0;
#define RDFSBASE_LEN 5 //Instruction length

void rdfsbase_sigill_handler(int sig, siginfo_t *si, void *data) {
    rdfsbase_caused_sigill = 1;

    // Skip instruction
    ucontext_t *uc = (ucontext_t *)data;
    uc->uc_mcontext.gregs[REG_RIP] += RDFSBASE_LEN;
}

/* Checks whether we can us FSGSBASE instructions within the enclave
   NOTE: This overrides previously set SIGILL handlers! */
void set_tls(enclave_config_t* conf) {
#ifdef SGXLKL_HW
    // We need to check whether we can support TLS in hardware mode or not This
    // is only possible if control register bit CR4.FSGSBASE is set that allows
    // us to set the FS segment base from userspace when context switching
    // between lthreads within the enclave.

    // All SGX-capabale CPUs should support the FSGSBASE feature, so we won't
    // check CPUID here. However, we do have to check whether the control
    // register bit is set. Currently, the only way to do this seems to be by
    // actually using one of the FSGSBASE instructions to check whether it
    // causes a #UD exception.
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = rdfsbase_sigill_handler;
    if (sigaction(SIGILL, &sa, NULL) == -1) {
        sgxlkl_warn("Failed to register SIGILL handler. Only limited thread-local storage support will be available.\n");
        return;
    }

    // If the following instruction causes a segfault, we won't be able to use
    // WRFSBASE to set the FS segment base inside the enclave.
    volatile unsigned long x;
    __asm__ volatile ( "rdfsbase %0" : "=r" (x) );
    conf->fsgsbase = !rdfsbase_caused_sigill;
# else
    conf->fsgsbase = 0;
#endif
}

/* Set up wireguard configuration */
void set_wg(enclave_config_t *conf) {
    struct enclave_wg_config *wg;
    wg = (struct enclave_wg_config *)malloc(sizeof(struct enclave_wg_config));

    char *wg_ip_str = sgxlkl_config_str(SGXLKL_WG_IP);
    if (inet_pton(AF_INET, wg_ip_str, &wg->ip) != 1) {
        free(wg);
        sgxlkl_fail("Invalid Wireguard IPv4 address %s\n", wg_ip_str);
    }

    wg->listen_port = (uint16_t) sgxlkl_config_uint64(SGXLKL_WG_PORT);
    wg->key = sgxlkl_config_str(SGXLKL_WG_KEY);

    conf->wg = wg;

    int num_peers = 0;
    char *peers_str = sgxlkl_config_str(SGXLKL_WG_PEERS);
    if (peers_str[0]) {
        num_peers++;
        for (int i = 0; peers_str[i]; i++) {
            if (peers_str[i] == ',') num_peers++;
        }
    }

    wg->num_peers = 0;
    if (!num_peers) return;

    // Allocate space for wg peer configuration
    wg->peers = (struct enclave_wg_peer_config*) malloc(sizeof(struct enclave_wg_peer_config) * num_peers);
    while (*peers_str) {
        char *key = peers_str;
        char *ips = strchrnul(key, ':');
        *ips = '\0';
        ips++;
        char *ips_end = strchrnul(ips, ':');
        *ips_end = '\0';
        char *endpoint = ++ips_end;
        peers_str = strchrnul(endpoint, ',');
        if (*peers_str == ',') {
            *peers_str = '\0';
            peers_str++;
            while(*peers_str == ' ' || *peers_str == ',') peers_str++;
        }

        wg->peers[wg->num_peers].key = key;
        wg->peers[wg->num_peers].allowed_ips = ips;
        wg->peers[wg->num_peers].endpoint = endpoint;
        wg->num_peers++;
    }
}

#ifndef SGXLKL_RELEASE
void set_app_config(enclave_config_t* conf, char *app_config_path) {
    int fd;
    if ((fd = open(app_config_path, O_RDONLY)) < 0)
        sgxlkl_fail("Failed to open %s: %s.\n", app_config_path, strerror(errno));

    off_t len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char *buf = (char *) malloc(len + 1);
    ssize_t ret;
    int off = 0;
    while ((ret = read(fd, &buf[off], len - off)) > 0) {
        off += ret;
    }
    buf[len] = 0;
    close(fd);

    if (ret < 0)
        sgxlkl_fail("Failed to read %s: %s.\n", app_config_path, strerror(errno));

    conf->app_config = buf;
}
#endif /* SGXLKL_RELEASE */

/* Parses the string provided as config for CPU affinity specifications. The
 * specification must consist of a comma-separated list of core IDs. It can
 * contain ranges. For example, "0-2,4" is a valid specification.
 * This function will allocate an array of all specified core IDs and stores
 * it's address at **cores. The number of valid array entries is stored at
 * cores_len.
 *
 * The memory allocated for the array should be free'd by the caller.
 */
void parse_cpu_affinity_params(char *config, int **cores, size_t *cores_len) {
    *cores = NULL;
    *cores_len = 0;

    if (!config || !strlen(config)) {
        return;
    }

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    // For simplicitly we allocate an array of size nproc to hold all cores
    // that are to be used. When the affinity is set to use a subset of cores,
    // *cores_len will reflect this.
    *cores = malloc(sizeof(int)*nproc);

    char *curr_ptr = config;
    long val = 0, range_start = -1;
    while (*curr_ptr && *cores_len < nproc) {
        switch (*curr_ptr) {
        case '0' ... '9': {
            // strtol will advance curr_ptr to the next non-digit character.
            val = strtol(curr_ptr, &curr_ptr, 10);
            if (val < 0 || val >= nproc) {
                fprintf(stderr, "[    SGX-LKL   ] Invalid CPU affinity range: %s, value %lu is larger or equal than the number of available cores (%lu).\n", config, val, nproc);
                return;
            } else if (range_start < 0) {
                (*cores)[(*cores_len)++] = (int) val;
            } else { // Range (range_start has already been added)
                for (; val > range_start && *cores_len < nproc; val--) {
                    (*cores)[(*cores_len)++] = (int) val;
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
            fprintf(stderr, "[    SGX-LKL   ] Invalid CPU affinity range: %s\n", config);
            return;
        }
    }
}

#ifdef SGXLKL_HW
void do_cpuid(unsigned int* reg) {
    __asm__ __volatile__ ("cpuid":\
            "=a" (reg[0]), "=b" (reg[1]), "=c" (reg[2]), "=d" (reg[3]) :\
            "a" (reg[0]), "c"(reg[2]));
}

void* enclave_thread(void* parm) {
    args_t* args = (args_t*)parm;
    uint64_t ret[2];
    int exit_code = 0;
    my_tcs_id = args->tcs_id;
    while (!__state_exiting) {
        enter_enclave(args->tcs_id, args->call_id, args->args, ret);
#ifdef DEBUG
        __sync_fetch_and_add(&_enclave_exit_stats[ret[0]], 1);
#endif /* DEBUG */
        switch (ret[0]) {
            case SGXLKL_EXIT_TERMINATE: {
                __state_exiting = 1;
                exit_code = ret[1];
                exit(exit_code);
            }
            case SGXLKL_EXIT_CPUID: {
                unsigned int* reg = (unsigned int*)ret[1];
                do_cpuid(reg);
                args->call_id = SGXLKL_ENTER_RESUME;
                break;
            }
            case SGXLKL_EXIT_SLEEP: {
                struct timespec sleep = {0, ret[1]};
                nanosleep(&sleep, NULL);
                args->call_id = SGXLKL_ENTER_RESUME;
                break;
            }
            case SGXLKL_EXIT_ERROR: {
                sgxlkl_fail("Error inside enclave, error code: %lu \n", ret[1]);
            }
            case SGXLKL_EXIT_DORESUME: {
                eresume(my_tcs_id);
            }
            case SGXLKL_EXIT_REPORT: {
                uint32_t quote_size;
                sgx_quote_t *quote = aesm_alloc_quote(&quote_size);
                if (!quote)
                    sgxlkl_fail("Could not allocate memory for SGX quote.\n");
                get_quote(*(sgx_report_t **)ret[1], quote, quote_size);

                attestation_info_t *att_info = (attestation_info_t*) ret[1];
                att_info->quote = quote;
                att_info->quote_size = quote_size;

                if (sgxlkl_config_str(SGXLKL_IAS_SPID)) {
                    if (!_attn_config.ias_key_file && sgxlkl_config_bool(SGXLKL_VERBOSE))
                        sgxlkl_info("No IAS key file provided (via SGXLKL_IAS_KEY_FILE). Skipping IAS attestation...\n");
                    else if (!_attn_config.ias_cert_file && sgxlkl_config_bool(SGXLKL_VERBOSE))
                        sgxlkl_info("No IAS certificate provided (via SGXLKL_IAS_CERT). Skipping IAS attestation...\n");

                    if (_attn_config.ias_key_file && _attn_config.ias_cert_file)
                        att_info->ias_report = get_attestation_report(quote, quote_size);
                }


                args->call_id = SGXLKL_ENTER_RESUME;
                break;
            }
            default:
                fprintf(stderr, "Unexpected exit reason from enclave: %lu.\n", ret[0]);
        }
    }

done:
    return 0;
}
#endif

#ifdef SGXLKL_HW

void forward_signal(int signum, void *handler_arg) {
    uint64_t call_id = SGXLKL_ENTER_HANDLE_SIGNAL;
    uint64_t ret[2];
    void * arg;
    enclave_signal_info_t siginfo;
    siginfo.signum = signum;
    siginfo.arg = handler_arg;
    arg = &siginfo;
reenter:
    if (__state_exiting) return;
    enter_enclave(my_tcs_id, call_id, arg, ret);
#ifdef DEBUG
    __sync_fetch_and_add(&_enclave_exit_stats[ret[0]], 1);
#endif /* DEBUG */
    switch (ret[0]) {
        case SGXLKL_EXIT_CPUID: {
            unsigned int* reg = (unsigned int*)ret[1];
            do_cpuid(reg);
            call_id = SGXLKL_ENTER_RESUME;
            goto reenter;
        }
        case SGXLKL_EXIT_DORESUME: {
            return;
        }
        case SGXLKL_EXIT_TERMINATE: {
            __state_exiting = 1;
            int exit_code = (int)ret[1];
            exit(exit_code);
        }
        default:
            fprintf(stderr, "Unexpected exit reason from signal handler.\n");
            //TODO: Other exit reasons (possible for SIGSEGV)
    }
}

void sigill_handler(int sig, siginfo_t *si, void *unused) {
    uint64_t low, high;
    uint64_t rsi;
    /* do rdtsc just in case */
    __asm("rdtscp" : "=a"(low), "=d"(high) : : "rcx");
    rsi = (high << 32) + low;
    forward_signal(SIGILL, (void*) rsi);
}

void sigsegv_handler(int sig, siginfo_t *si, void *unused) {
    // Just forward signal
    forward_signal(SIGSEGV, (void*) si);
}

void sigfpe_handler(int sig, siginfo_t *si, void *unused) {
    // Just forward signal
    forward_signal(SIGFPE, (void*) si);
}

void init_attestation(enclave_config_t *conf) {
    char *spid, *spid_str;
    ssize_t spid_len;

    // Initialize quote, get target info from quoting enclave.
    // The target info is needed within the enclave to generate a report for
    // the quoting enclave.
    sgx_target_info_t *ti = malloc(sizeof(sgx_target_info_t));

    sgx_epid_group_id_t gid;
    if (aesm_init_quote(ti, &gid)) {
        sgxlkl_warn("Failed to initialize quote. Remote attestation will not be possible.\n");
        free(ti);
        return;
    }
    conf->quote_target_info = ti;

    // Set up attestation config
    spid_str = sgxlkl_config_str(SGXLKL_IAS_SPID);
    if (spid_str) {
        spid_len = hex_to_bytes(spid_str, &spid);
        if (spid_len != sizeof(sgx_spid_t))
            sgxlkl_fail("Provided IAS SPID \"%s\" invalid.\n", spid_str);
        memcpy(&_attn_config.spid, spid, spid_len);

        char *quote_type = sgxlkl_config_str(SGXLKL_IAS_QUOTE_TYPE);
        _attn_config.quote_type = !strcmp(quote_type, "Unlinkable") ? SGX_UNLINKABLE_SIGNATURE : SGX_LINKABLE_SIGNATURE;

        _attn_config.ias_key_file = sgxlkl_config_str(SGXLKL_IAS_KEY_FILE);
        _attn_config.ias_cert_file = sgxlkl_config_str(SGXLKL_IAS_CERT);
        _attn_config.ias_server = sgxlkl_config_str(SGXLKL_IAS_SERVER);
    } else if (sgxlkl_config_bool(SGXLKL_VERBOSE))
        sgxlkl_info("No IAS SPID provided, enclave quote will not be verifiable by IAS.\n");

    sgx_report_t *report = malloc(sizeof(sgx_report_t));
    conf->report = report;

    conf->report_nonce = sgxlkl_config_uint64(SGXLKL_REPORT_NONCE);
}

void get_quote(sgx_report_t *report, sgx_quote_t *quote, uint32_t quote_size) {
    if (aesm_get_quote(&_attn_config.spid,
                      _attn_config.quote_type,
                      report,
                      quote,
                      quote_size)) {
        sgxlkl_warn("Failed to get quote from AESM. Remote attestation will not be possible.\n");
        return;
    }

    if (sgxlkl_config_bool(SGXLKL_VERBOSE)) {
        sgx_report_body_t* body = &quote->report_body;
        sgxlkl_info("Received quote from launch enclave:\n");
        sgxlkl_info(" MRENCLAVE: ");
        for (int i=0; i < SGX_HASH_SIZE; ++i) fprintf(stderr, "%02x", body->mr_enclave.m[i]);
        fprintf(stderr, "\n");
        sgxlkl_info(" MRSIGNER:  ");
        for (int i=0; i < SGX_HASH_SIZE; ++i) fprintf(stderr, "%02x", body->mr_signer.m[i]);
        fprintf(stderr, "\n");
    }
}

attestation_verification_report_t *get_attestation_report(sgx_quote_t *quote, size_t quote_size) {
    attestation_verification_report_t *attn_report = malloc(sizeof(*attn_report));
    if (ias_get_attestation_verification_report(quote,
                                            quote_size,
                                            &_attn_config,
                                            attn_report,
                                            sgxlkl_config_bool(SGXLKL_VERBOSE))) {
        free(attn_report);
        return NULL;
    }

    return attn_report;
}

#endif

#ifdef DEBUG
void __attribute__ ((noinline)) __gdb_hook_starter_ready(enclave_config_t *conf, char *libsgxlkl_path) {
    __asm__ volatile ( "nop" : : "m" (conf), "m" (libsgxlkl_path) );
}

void print_host_syscall_stats() {
    // If we are exiting from the SIGINT handler, we already printed the
    // syscall stats.
    if (_sigint_handling)
        return;

    printf("Enclave exits: \n");
    printf("Calls      Exit reason          No.\n");
    for (int i = 0; i < MAX_EXIT_REASON_NUMBER; i++) {
        if(_enclave_exit_stats[i]) {
            printf("%10lu %20s %d\n", _enclave_exit_stats[i],  (i < sizeof(_enclave_exit_reasons)) ? _enclave_exit_reasons[i] : "UNKNOWN", i);
        }
    }

// Commented out for now as any additional computation in the AEX handler seems
// to lead to deadlocks while running under gdb in HW mode and potentially
// under other circumstances as well.
//    printf("\nHardware exceptions: %lu\n", hw_exceptions);

    printf("\nHost syscalls: \n");
    printf("Calls      Syscall              No.\n");
    for (int i = 0; i < MAX_SYSCALL_NUMBER; i++) {
        if(_host_syscall_stats[i]) {
            printf("%10lu %20s %d\n", _host_syscall_stats[i],  (i < sizeof(_syscall_names)) ? _syscall_names[i] : "UNKNOWN", i);
        }
    }
}

void stats_sigint_handler(int signo) {
        if (_sigint_handling)
            return;

        print_host_syscall_stats();

        _sigint_handling = 1;
        char response[2];
        fprintf(stderr, "\nDo you want to quit (continue execution otherwise)? [y/n]");
        scanf("%1s", &response[0]);
        if (response[0] == 'y' || response[0] == 'Y') {
            exit(EXIT_SUCCESS);
        }

        _sigint_handling = 0;
}
#endif /* DEBUG */

void check_envs(const char **pres, char **envp, const char *warn_msg) {
    char envname[128];
    for (char **env = envp; *env != 0; env++) {
        for (int i = 0; i < sizeof(pres)/sizeof(pres[0]); i++) {
            if (strncmp(pres[i], *env, strlen(pres[i])) == 0) {
                snprintf(envname, MIN(sizeof(envname), strchrnul(*env, '=') - *env + 1), "%s", *env);
                if (getenv_bool(envname, 0)) {
                    fprintf(stderr, warn_msg, envname);
                }
            }
        }
    }
}

void check_envs_all(char ** envp) {
#ifndef DEBUG
    const char *dbg_pres[] = {"SGXLKL_TRACE_", "SGXLKL_PRINT_"};
    check_envs(dbg_pres, envp, "[    SGX-LKL   ] Warning: %s ignored in non-debug mode.\n");
#endif /* DEBUG */
}

void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);

#ifdef DEBUG
    if (sgxlkl_config_bool(SGXLKL_PRINT_HOST_SYSCALL_STATS)) {
        atexit(&print_host_syscall_stats);
        sa.sa_flags = SA_SIGINFO;
        sa.sa_handler = stats_sigint_handler;
        if (sigaction(SIGINT, &sa, NULL) == -1)
            sgxlkl_fail("Failed to register SIGINT handler\n");
    }
#endif /* DEBUG */

    /* ignore sigpipe? */
    if (!sgxlkl_config_bool(SGXLKL_SIGPIPE)) {
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = SIG_IGN;
        sa.sa_flags = 0;
        sigaction(SIGPIPE, &sa, 0);
    }

#ifdef SGXLKL_HW
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigill_handler;
    if (sigaction(SIGILL, &sa, NULL) == -1)
        sgxlkl_fail("Failed to register SIGILL handler\n");

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigsegv_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        sgxlkl_fail("Failed to register SIGSEGV handler\n");

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigfpe_handler;
    if (sigaction(SIGFPE, &sa, NULL) == -1)
        sgxlkl_fail("Failed to register SIGFPE handler\n");
#endif /* SGXLKL_HW */
}

#ifndef SGXLKL_HW
/* Called by an enclave thread on exit in simulation mode. This is needed to be
 * able to call the glibc versions of the pthread_* functions. */
void sgxlkl_sim_exit_handler(int ec) {
    // Signal main thread outside to exit.
    sim_exit_code = ec;
    int ret;
    if (ret = pthread_mutex_lock(&sim_exit_mtx))
        sgxlkl_fail("Failed to acquire enclave exit lock.\n");
    if (ret = pthread_cond_signal(&sim_exit_cv))
        sgxlkl_fail("Failed to acquire enclave exit lock.\n");
    pthread_mutex_unlock(&sim_exit_mtx);
}

static void setup_sim_exit_handler(struct enclave_config *encl) {
    /* We use a condition variable to wait for enclave threads to exit in SIM mode.
       This allows us to to do cleanup work when exiting. We can't exit from the
       enclave in SIM mode directly:

       1) If we terminate by directly performing exit/exit_group syscalls, exit
       handlers registered in this file won't be called.  2) We can't call the glibc
       exit function from an enclave thread directly due to glibc storing a pointer
       guard used for atexit function mangling in the thread control block (TCB). In
       order to support thread-local storage for user-level application threads within
       the enclave we se our own TCBs so that pointer guards don't match and the glibc
       exit function would fail when demangling exit function pointers.

       In HW mode, this is not an issue as leaving the enclave restores the FS segment
       base on exit. The segment base then points to the correct glibc pthread TCB. */
    int ret;
    if (ret = pthread_cond_init(&sim_exit_cv, NULL))
        sgxlkl_fail("Could not initialize exit condition variable: %s\n", strerror(ret));
    if (ret = pthread_mutex_init(&sim_exit_mtx, NULL))
        sgxlkl_fail("Could not initialize exit mutex: %s\n", strerror(ret));
    if (ret = pthread_mutex_lock(&sim_exit_mtx))
        sgxlkl_fail("Could not lock exit mutex: %s.\n", strerror(ret));

    encl->sim_exit_handler = &sgxlkl_sim_exit_handler;
}
#endif /* !SGXLKL_HW */

static void sgxlkl_cleanup(void) {
    // Close disk image fds
    while (_encl_disk_cnt) {
        close(_encl_disks[--_encl_disk_cnt].fd);
    }
}

/* Determines path of libsgxlkl.so (lkl + musl) */
void get_libsgxlkl_path(char *path_buf, size_t len) {
    /* Look for libsgxlkl.so in:
     *  1. .
     *  2. ../lib
     *  3. /lib
     *  4. /usr/local/lib
     *  5. /usr/lib
     *
     * NOTE: The code below relies on the fact that relative paths
     * are checked first.
    */
    char *search_in = ".:../lib:/lib:/usr/local/lib:/usr/lib";

    ssize_t q;
    char *path_sep;
    q = readlink("/proc/self/exe", path_buf, len);
    if (q <= 0 || (path_sep = strrchr(path_buf, '/')) == NULL)
        sgxlkl_fail("Unable to determine path of sgx-lkl-run.\n");

    char *base = search_in;
    size_t base_len = 0;
    while ((base_len = strcspn(base, ":")) > 0) {
        // Relative or absolute path
        char *buf;
        size_t max_len;
        if (!strncmp(base, ".", 1)) {
            buf = path_sep + 1;
            max_len = len - (path_sep + 1 - path_buf);
        } else {
            buf = path_buf;
            max_len = len;
        }

        if (snprintf(buf, max_len, "%.*s/%s", (int) base_len, base, "libsgxlkl.so") < max_len) {
            // If accessible, path found.
            if (!access(path_buf, R_OK))
                return;
        }

        base += base_len;
        base += strspn(base, ":");
    }

    sgxlkl_fail("Unable to locate libsgxlkl.so.\n");
}

//Assumes format --longopt[=optarg] or -shortopt[=optarg]
int getopt_sgxlkl(int argc, char *argv[], struct option long_options[]) {
    optarg = NULL;
    optopt = 0;
    if (optind >= argc)
        return -1;

    char *arg = argv[optind];
    if (arg[0] != '-')
        return -1;

    struct option *opt = long_options;
    for (; opt->name; opt++) {
        size_t optidx = 1;
        // Long opt
        if (arg[1] == '-' && !strncmp(opt->name, &arg[2], strlen(opt->name))) {
            optidx += 1 + strlen(opt->name);
        // Short opt
        } else if (arg[1] == opt->val) {
            optidx += 1;
        } else
            continue;

        // Handle no argument options
        if (opt->has_arg == no_argument)
            if (arg[optidx])
                return -1;
            else
                break;

        // Handle required argument options
        if (opt->has_arg == required_argument)
            if (arg[optidx] == '=') {
                optidx++;
            } else if (arg[optidx] == '\0') {
                if (++optind >= argc) {
                    fprintf(stderr, "Error: %s requires argument.\n", opt->name);
                    return '?';
                } else
                    optidx = 0;
            }
            optarg = &argv[optind][optidx];
            break;
    }

    if (opt) {
        optind++;
        return opt->val;
    } else
        return -1;
}

int main(int argc, char *argv[], char *envp[]) {
    size_t ecs = 0;
    size_t ntsyscall = 1;
    size_t ntenclave = 1;
    pthread_t *ts;
    enclave_config_t encl = {0};
    char *root_hd, *app_config;
    char** auxvp;
    int i, r, rtprio;
    void *_retval;
    int encl_mmap_flags;
    pthread_attr_t eattr;
    cpu_set_t set;
    int *ethreads_cores, *sthreads_cores;
    size_t ethreads_cores_len, sthreads_cores_len;

    // We reuse getopt features but do the parsing ourselves (not via
    // getopt_long) as we must allow unrecognized options. We need to stop
    // parsing as soon as we hit the first unrecognized option.
    static struct option long_options[] = {
        {"version",  no_argument,       0, 'v' },
        {"usage",    no_argument,       0, 'u' },
        {"help",     no_argument,       0, 'h' },
        {"help-tls", no_argument,       0, 't' },
        {"config",   required_argument, 0, 'c' },
        {"app",      required_argument, 0, 'a' },
        {0,          0,                 0,  0  }
    };

    int c;
    char *err;
    while ((c = getopt_sgxlkl(argc, argv, long_options)) != -1) {
        switch (c) {
        case 'v':
            version();
            exit(EXIT_SUCCESS);
        case 'u':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'h':
            help(argv[0]);
            exit(EXIT_SUCCESS);
        case 't':
            help_tls();
            exit(EXIT_SUCCESS);
        case 'c':
            if (parse_sgxlkl_config(optarg, &err))
                sgxlkl_fail("Failed to parse configuration file: %s\n", err);
            break;
        case 'a':
            app_config = optarg;
            break;
        default:
            // Should never happen
            sgxlkl_fail("Unexpected command line option: %c\n", c);
        }
    }

    encl.argc = argc - optind;
    encl.argv = argv + optind;

    // Determine path to root disk. Either configured via env/json config or
    // as first command line argument.
    if (sgxlkl_configured(SGXLKL_HD)) {
        root_hd = sgxlkl_config_str(SGXLKL_HD);
    } else if (encl.argc) {
        root_hd = encl.argv[0];
        encl.argc -= 1;
        encl.argv += 1;
    } else {
        sgxlkl_warn("Insufficient arguments. No root disk image path provided.\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

// In release mode any host-provided application configuration is ignored
// and has to be provided remotely.
#ifndef SGXLKL_RELEASE
    // Check if app_config has been provided
    if (app_config)
        set_app_config(&encl, app_config);
    else if (sgxlkl_configured(SGXLKL_APP_CONFIG))
        encl.app_config = sgxlkl_config_str(SGXLKL_APP_CONFIG);
    else if(!encl.argc && !sgxlkl_config_bool(SGXLKL_REMOTE_CONFIG)) {
        sgxlkl_warn("Insufficient arguments. No application path provided.\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
#endif /* SGXLKL_RELEASE */

    const size_t pagesize = sysconf(_SC_PAGESIZE);
    ecs = sizeof(encl) + (pagesize - (sizeof(encl)%pagesize));

    /* Print warnings for ignored options, e.g. for debug options in non-debug mode. */
    check_envs_all(envp);

#ifdef SGXLKL_HW
    encl.mode = SGXLKL_HW_MODE;
#else
    encl.mode = SGXLKL_SIM_MODE;
#endif /* SGXLKL_HW */

    // Use numbers of cores as default.
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    ntenclave = sgxlkl_config_uint64(SGXLKL_ETHREADS);

    // Sthread config
    backoff_maxpause = sgxlkl_config_uint64(SGXLKL_SSPINS);
    backoff_factor = sgxlkl_config_uint64(SGXLKL_SSLEEP);

    // Ethread config
    encl.stacksize = sgxlkl_config_uint64(SGXLKL_STACK_SIZE);
    encl.max_user_threads = sgxlkl_config_uint64(SGXLKL_MAX_USER_THREADS);
    encl.maxsyscalls = encl.max_user_threads + sgxlkl_config_uint64(SGXLKL_ETHREADS);
    encl.espins = sgxlkl_config_uint64(SGXLKL_ESPINS);
    encl.esleep = sgxlkl_config_uint64(SGXLKL_ESLEEP);
    encl.verbose = sgxlkl_config_bool(SGXLKL_VERBOSE);
    encl.kernel_verbose = sgxlkl_config_bool(SGXLKL_KERNEL_VERBOSE);
    encl.kernel_cmd = sgxlkl_config_str(SGXLKL_CMDLINE);
    encl.remote_attest_port = (uint16_t) sgxlkl_config_uint64(SGXLKL_REMOTE_ATTEST_PORT);
    encl.remote_cmd_port = (uint16_t) sgxlkl_config_uint64(SGXLKL_REMOTE_CMD_PORT);
    encl.remote_cmd_eth0 = sgxlkl_config_bool(SGXLKL_REMOTE_CMD_ETH0);
    encl.remote_config = sgxlkl_config_bool(SGXLKL_REMOTE_CONFIG);
    char *mmap_files = sgxlkl_config_str(SGXLKL_MMAP_FILES);
    encl.mmap_files = !strcmp(mmap_files, "Shared") ? ENCLAVE_MMAP_FILES_SHARED :
                     (!strcmp(mmap_files, "Private") ? ENCLAVE_MMAP_FILES_PRIVATE :
                     ENCLAVE_MMAP_FILES_NONE);
    set_sysconf_params(&encl, ntenclave);
    set_vdso(&encl);
    set_shared_mem(&encl);
    set_tls(&encl);
    set_wg(&encl);
    register_hds(&encl, root_hd);
    register_net(&encl, sgxlkl_config_str(SGXLKL_TAP),
                        sgxlkl_config_str(SGXLKL_IP4),
                        (int) sgxlkl_config_uint64(SGXLKL_MASK4),
                        sgxlkl_config_str(SGXLKL_GW4),
                        sgxlkl_config_str(SGXLKL_HOSTNAME));
    register_queues(&encl);

#ifdef SGXLKL_HW
    init_attestation(&encl);
#else
    setup_sim_exit_handler(&encl);
#endif

    // This has to be called after calling set_tls as set_tls registers a
    // temporary SIGILL handler.
    setup_signal_handlers();

    atexit(sgxlkl_cleanup);

    char libsgxlkl[PATH_MAX];
    get_libsgxlkl_path(libsgxlkl, PATH_MAX);

    parse_cpu_affinity_params(sgxlkl_config_str(SGXLKL_STHREADS_AFFINITY), &sthreads_cores, &sthreads_cores_len);
    parse_cpu_affinity_params(sgxlkl_config_str(SGXLKL_ETHREADS_AFFINITY), &ethreads_cores, &ethreads_cores_len);

    /* Initialize print spin locks */
    if (pthread_spin_init(&_stdout_print_lock, PTHREAD_PROCESS_PRIVATE) ||
        pthread_spin_init(&_stderr_print_lock, PTHREAD_PROCESS_PRIVATE) ) {
        sgxlkl_fail("Could not initialize print spin locks.\n");
    }

    /* Get system call thread number */
    ntsyscall = sgxlkl_config_uint64(SGXLKL_STHREADS);
    ts = calloc(sizeof(*ts), ntenclave + ntsyscall);
    if (ts == 0) sgxlkl_fail("Failed to allocate memory for thread identifiers: %s\n", strerror(errno));

#ifdef SGXLKL_HW
    /* Map enclave file into memory */
    int lkl_lib_fd;
    struct stat lkl_lib_stat;
    if(!(lkl_lib_fd = open(libsgxlkl, O_RDONLY)))
        sgxlkl_fail("Failed to open %s: %s\n", libsgxlkl, strerror(errno));

    if(fstat(lkl_lib_fd, &lkl_lib_stat) == -1)
        sgxlkl_fail("Failed to call fstat on %s: %s\n", libsgxlkl, strerror(errno));

    char* enclave_start = mmap(0, lkl_lib_stat.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, lkl_lib_fd, 0);

    init_sgx();
    if (sgxlkl_configured(SGXLKL_HEAP) || sgxlkl_configured(SGXLKL_KEY)) {
        if (!sgxlkl_configured(SGXLKL_KEY))
            sgxlkl_fail("Heap size but no enclave signing key specified. Please specify a signing key via SGXLKL_KEY.\n");
        enclave_update_heap(enclave_start, sgxlkl_config_uint64(SGXLKL_HEAP), sgxlkl_config_str(SGXLKL_KEY));
    }
    create_enclave_mem(enclave_start, sgxlkl_config_bool(SGXLKL_NON_PIE), &__sgxlklrun_text_segment_start);

    // Check if there are enough TCS for all ethreads.
    int num_tcs = get_tcs_num();
    if (num_tcs == 0) sgxlkl_fail("No TCS number specified \n");
    if (num_tcs < ntenclave) sgxlkl_fail("Not enough TCS \n");
#else
    /* Initialize heap memory */
    encl.heapsize = sgxlkl_config_uint64(SGXLKL_HEAP);
    encl_mmap_flags = MAP_PRIVATE|MAP_ANONYMOUS;
    if (sgxlkl_config_bool(SGXLKL_NON_PIE)) {
        if ((char*) SIM_NON_PIE_ENCL_MMAP_OFFSET + encl.heapsize > &__sgxlklrun_text_segment_start) {
            sgxlkl_fail("SGXLKL_HEAP must be smaller than %lu bytes to not overlap with sgx-lkl-run when SGXLKL_NON_PIE is set to 1.\n", (size_t) (&__sgxlklrun_text_segment_start - SIM_NON_PIE_ENCL_MMAP_OFFSET));
        }
        encl_mmap_flags |= MAP_FIXED;
    }
    encl.heap = mmap((void*) SIM_NON_PIE_ENCL_MMAP_OFFSET, encl.heapsize, PROT_EXEC|PROT_READ|PROT_WRITE, encl_mmap_flags, -1, 0);
    if (encl.heap == MAP_FAILED)
        sgxlkl_fail("Failed to allocate memory for enclave heap: %s\n", strerror(errno));

    /* Load libsgxlkl */
    struct encl_map_info encl_map;
    load_elf(libsgxlkl, &encl_map);
    if (encl_map.base < 0) sgxlkl_fail("Could not load liblkl.\n");

    encl.base = encl_map.base;
    encl.ifn = encl_map.entry_point;
#endif

    /* Launch system call threads */
    for (i = 0; i < ntsyscall; i++) {
        pthread_attr_init(&eattr);
        CPU_ZERO(&set);
        if (sthreads_cores_len) {
            CPU_SET(sthreads_cores[i % sthreads_cores_len] , &set);
        } else {
            CPU_SET(i%nproc, &set);
        }
        pthread_attr_setaffinity_np(&eattr, sizeof(set), &set);
        pthread_create(&ts[i], &eattr, host_syscall_thread, &encl);
        pthread_setname_np(ts[i], "HOST_SYSCALL");
    }

#ifdef DEBUG
    __gdb_hook_starter_ready(&encl, libsgxlkl);
#endif

    // Find aux vector (after envp vector)
    for (auxvp = envp; *auxvp; auxvp++);
    encl.auxv = (Elf64_auxv_t*) (++auxvp);

#ifdef SGXLKL_HW
    args_t a[ntenclave];
#else
    // Run the relocation routine inside the new environment
    pthread_t init_thread;
    void* continuation_location;
    r = pthread_create(&init_thread, NULL, (void *)encl.ifn, &encl);
    pthread_setname_np(init_thread, "INIT");
    pthread_join(init_thread, &continuation_location);
#endif

    rtprio = sgxlkl_config_bool(SGXLKL_REAL_TIME_PRIO);
    for (i = 0; i < ntenclave; i++) {
        pthread_attr_init(&eattr);
        CPU_ZERO(&set);
        if (ethreads_cores_len) {
            CPU_SET(ethreads_cores[i % ethreads_cores_len] , &set);
        } else {
            CPU_SET(i%nproc, &set);
        }
        pthread_attr_setaffinity_np(&eattr, sizeof(set), &set);

        if (rtprio) {
            struct sched_param schparam = {0};
            schparam.sched_priority = 10;
            pthread_attr_setschedpolicy(&eattr, SCHED_FIFO);
            pthread_attr_setschedparam(&eattr, &schparam);
            pthread_attr_setinheritsched(&eattr, PTHREAD_EXPLICIT_SCHED);
        }
#ifdef SGXLKL_HW
        a[i].call_id = SGXLKL_ENTER_THREAD_CREATE;
        a[i].args = &encl;
        a[i].tcs_id = i;
        r = pthread_create(&ts[ntsyscall + i], &eattr, (void *)enclave_thread, (void *) &a[i]);
#else
        r = pthread_create(&ts[ntsyscall + i], &eattr, (void *)continuation_location, &encl);
#endif
        pthread_setname_np(ts[ntsyscall + i], "ENCLAVE");
        if (rtprio && r == EPERM) {
            printf("%s", "Not allowed to create thread with realtime priority. Exiting. Use\n"
                    "# echo '*         -       rtprio          80' >> /etc/security/limits.conf\n"
                    "and relogin.\n");
            exit(EXIT_FAILURE);
        }
    }

#ifdef SGXLKL_HW
    /* Once an enclave thread calls exit in HW mode we exit anyway. */
    for (i = 0; i < ntenclave; i++)
        pthread_join(ts[ntsyscall + i], &_retval);
#else
    pthread_cond_wait(&sim_exit_cv, &sim_exit_mtx);
    exit(sim_exit_code);
#endif
}

