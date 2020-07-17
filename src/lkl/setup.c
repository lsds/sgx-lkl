#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/random.h>
#include <stdlib.h>
#define _GNU_SOURCE // Needed for strchrnul
#include <lkl.h>
#include <lkl_host.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <syscall.h>
#include <time.h>

#include <lkl.h>
#include <lkl_host.h>
#include <unistd.h>

#include "enclave/enclave_oe.h"
#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/wireguard.h"
#include "enclave/wireguard_util.h"
#include "libcryptsetup.h"
#include "libdevmapper.h"
#include "lkl/disk.h"
#include "lkl/ext4_create.h"
#include "lkl/posix-host.h"
#include "lkl/setup.h"
#include "lkl/syscall-overrides.h"
#include "lkl/virtio_device.h"
#include "lkl/virtio_net.h"

#include "libcryptsetup.h"
#include "libdevmapper.h"

#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/wireguard.h"
#include "enclave/wireguard_util.h"
#include "shared/env.h"
#include "shared/sgxlkl_enclave_config.h"
#include "shared/timer_dev.h"

#include "openenclave/corelibc/oestring.h"

#define UMOUNT_DISK_TIMEOUT 2000

// Block size in bytes of the ext4 filesystem for newly created empty disks.
// Should be a multiple of the kernel page size to avoid
// issues with sparse/unwiped dm-integrity devices.
#define CREATED_DISK_EXT4_BLOCK_SIZE 4096

// The size of the generated key in bits for newly created empty disks.
#define CREATED_DISK_KEY_LENGTH 512

// The assumed size overhead for encrypted & integrity-protected disks
// as ratio of the original disk size.
#define CREATED_DISK_ENCRYPTION_OVERHEAD 0.15

#define BOOTARGS_LEN 128

/* Console argument for bootargs */
#define BOOTARGS_CONSOLE_OPTION "console=hvc0"
#define BOOTARGS_QUIET_OPTION "quiet"

int sethostname(const char*, size_t);

int sgxlkl_trace_lkl_syscall = 0;
int sgxlkl_trace_internal_syscall = 0;
int sgxlkl_trace_ignored_syscall = 0;
int sgxlkl_trace_unsupported_syscall = 0;
int sgxlkl_trace_redirect_syscall = 0;
int sgxlkl_trace_mmap = 0;
int sgxlkl_trace_signal = 0;
int sgxlkl_trace_thread = 0;
int sgxlkl_trace_disk = 0;
int sgxlkl_use_host_network = 0;
int sgxlkl_mtu = 0;

extern struct timespec sgxlkl_app_starttime;

/* Function to setup bounce buffer in LKL */
extern void initialize_enclave_event_channel(
    enc_dev_config_t* enc_dev_config,
    size_t evt_channel_num);

extern void lkl_virtio_netdev_remove(void);

/* Set by sgx-lkl-disk measure */
const uint8_t disk_dm_verity_root_hash[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void lkl_prepare_rootfs(const char* dirname, int perm)
{
    int err = lkl_sys_access(dirname, /*LKL_S_IRWXO*/ F_OK);
    if (err < 0)
    {
        if (err == -LKL_ENOENT)
            err = lkl_sys_mkdir(dirname, perm);
        if (err < 0)
        {
            sgxlkl_fail("Unable to mkdir %s: %s\n", dirname, lkl_strerror(err));
        }
    }
}

static void lkl_copy_blkdev_nodes(const char* srcdir, const char* dstdir)
{
    int err = 0;
    struct lkl_dir* dir = lkl_opendir(srcdir, &err);
    if (dir == NULL || err != 0)
    {
        sgxlkl_fail("Unable to opendir(%s)\n", srcdir);
    }

    char srcbuf[512] = {0};
    char dstbuf[512] = {0};
    strncpy(srcbuf, srcdir, sizeof(srcbuf));
    strncpy(dstbuf, dstdir, sizeof(dstbuf));
    int srcdir_len = strlen(srcbuf);
    int dstdir_len = strlen(dstbuf);
    if (srcbuf[srcdir_len - 1] != '/')
        srcbuf[srcdir_len++] = '/';
    if (dstbuf[dstdir_len - 1] != '/')
        dstbuf[dstdir_len++] = '/';
    struct lkl_linux_dirent64* dev = NULL;
    while ((dev = lkl_readdir(dir)) != NULL)
    {
        strncpy(srcbuf + srcdir_len, dev->d_name, sizeof(srcbuf) - srcdir_len);
        strncpy(dstbuf + dstdir_len, dev->d_name, sizeof(dstbuf) - dstdir_len);
        struct lkl_stat stat;
        err = lkl_sys_stat(srcbuf, &stat);
        if (err != 0)
        {
            sgxlkl_fail("lkl_sys_stat(%s) %s\n", srcbuf, lkl_strerror(err));
        }
        if (!LKL_S_ISBLK(stat.st_mode))
            continue;

        lkl_sys_unlink(dstbuf);
        err = lkl_sys_mknod(dstbuf, LKL_S_IFBLK | 0600, stat.st_rdev);
        if (err != 0)
        {
            sgxlkl_fail("lkl_sys_mknod(%s) %s\n", dstbuf, lkl_strerror(err));
        }
    }
    err = lkl_errdir(dir);
    if (err != 0)
    {
        sgxlkl_fail("lkl_readdir(%s) = %d\n", srcdir, err);
    }

    err = lkl_closedir(dir);
    if (err != 0)
    {
        sgxlkl_fail("lkl_closedir(%s) = %d\n", srcdir, err);
    }
}

static void lkl_mount_devtmpfs(const char* mntpoint)
{
    int err = lkl_sys_mount("devtmpfs", (char*)mntpoint, "devtmpfs", 0, NULL);
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mount(devtmpfs): %s\n", lkl_strerror(err));
    }
}

static void lkl_mount_shmtmpfs()
{
    int err = lkl_sys_mount("tmpfs", "/dev/shm", "tmpfs", 0, "rw,nodev");
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mount(tmpfs) (/dev/shm): %s\n", lkl_strerror(err));
    }
}

static void lkl_mount_tmpfs()
{
    int err = lkl_sys_mount("tmpfs", "/tmp", "tmpfs", 0, "mode=0777");
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mount(tmpfs): %s\n", lkl_strerror(err));
    }
}

static void lkl_mount_mntfs()
{
    int err = lkl_sys_mount("tmpfs", "/mnt", "tmpfs", 0, "mode=0777");
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mount(tmpfs): %s\n", lkl_strerror(err));
    }
}

static void lkl_mount_sysfs()
{
    int err = lkl_sys_mount("none", "/sys", "sysfs", 0, NULL);
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mount(sysfs): %s\n", lkl_strerror(err));
    }
}

static void lkl_mount_runfs()
{
    int err = lkl_sys_mount("tmpfs", "/run", "tmpfs", 0, "mode=0700");
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mount(tmpfs): %s\n", lkl_strerror(err));
    }
}

static void lkl_mount_procfs()
{
    int err = lkl_sys_mount("proc", "/proc", "proc", 0, NULL);
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mount(procfs): %s\n", lkl_strerror(err));
    }
}

static void lkl_mknods()
{
    lkl_sys_unlink("/dev/null");
    int err = lkl_sys_mknod("/dev/null", LKL_S_IFCHR | 0666, LKL_MKDEV(1, 3));
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mknod(/dev/null) %s\n", lkl_strerror(err));
    }
    lkl_sys_unlink("/dev/zero");
    err = lkl_sys_mknod("/dev/zero", LKL_S_IFCHR | 0666, LKL_MKDEV(1, 5));
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mknod(/dev/zero) %s\n", lkl_strerror(err));
    }
    lkl_sys_unlink("/dev/random");
    err = lkl_sys_mknod("/dev/random", LKL_S_IFCHR | 0444, LKL_MKDEV(1, 8));
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mknod(/dev/random) %s\n", lkl_strerror(err));
    }
    lkl_sys_unlink("/dev/urandom");
    err = lkl_sys_mknod("/dev/urandom", LKL_S_IFCHR | 0444, LKL_MKDEV(1, 9));
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mknod(/dev/urandom) %s\n", lkl_strerror(err));
    }
}

static int lkl_mount_blockdev(
    const char* dev_str,
    const char* mnt_point,
    const char* fs_type,
    int flags,
    const char* data)
{
    char _data[4096];
    int err;

    err = lkl_sys_access("/mnt", LKL_S_IRWXO);
    if (err < 0)
    {
        if (err == -LKL_ENOENT)
            err = lkl_sys_mkdir("/mnt", 0700);
        if (err < 0)
            goto fail;
    }

    // Create mount directory if it does not exist.
    // Allow existing directories so that disks can be mounted in read-only root
    // fs.
    const int mkdir_err = lkl_sys_mkdir(mnt_point, 0700);
    if (mkdir_err < 0 && mkdir_err != -LKL_EEXIST)
        goto fail;

    if (data)
    {
        strncpy(_data, data, sizeof(_data));
        _data[sizeof(_data) - 1] = 0;
    }
    else
    {
        _data[0] = 0;
    }

    err = lkl_sys_mount(
        (char*)dev_str, (char*)mnt_point, (char*)fs_type, flags, _data);
    if (err < 0)
    {
        if (mkdir_err >= 0)
            lkl_sys_rmdir(mnt_point);

        goto fail;
    }

fail:
    return err;
}

static void lkl_mount_overlay_tmpfs(const char* mnt_point)
{
    int err = lkl_sys_mount("tmpfs", (char*)mnt_point, "tmpfs", 0, "mode=0777");
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mount(tmpfs): %s\n", lkl_strerror(err));
    }
}

static void lkl_mount_overlayfs(
    const char* lower_dir,
    const char* upper_dir,
    const char* work_dir,
    const char* mnt_point)
{
    char opts[200];

    oe_snprintf(
        opts,
        sizeof(opts),
        "lowerdir=%s,upperdir=%s,workdir=%s",
        lower_dir,
        upper_dir,
        work_dir);
    int err = lkl_sys_mount("overlay", (char*)mnt_point, "overlay", 0, opts);
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_mount(overlayfs): %s\n", lkl_strerror(err));
    }
}

typedef struct
{
    bool create;
    const char* destination;
    size_t key_len;
    uint8_t* key;
    const char* key_id;
    bool fresh_key;
    bool readonly;
    const char* roothash;
    size_t roothash_offset;
    size_t size;
    bool overlay;
} disk_config_t;

struct lkl_crypt_device
{
    char* disk_path;
    int readonly;
    disk_config_t disk_config;
    char* crypt_name;
};

static void* lkl_activate_crypto_disk_thread(struct lkl_crypt_device* lkl_cd)
{
    int err;

    char* disk_path = lkl_cd->disk_path;

    struct crypt_device* cd;
    err = crypt_init(&cd, disk_path);
    if (err != 0)
    {
        sgxlkl_fail("crypt_init(): %s (%d)\n", strerror(-err), err);
    }

    err = crypt_load(cd, CRYPT_LUKS, NULL);
    if (err != 0)
    {
        sgxlkl_fail("crypt_load(): %s (%d)\n", strerror(-err), err);
    }

    uint8_t* key_outside = lkl_cd->disk_config.key;
    lkl_cd->disk_config.key = (uint8_t*)lkl_sys_mmap(
        NULL,
        lkl_cd->disk_config.key_len,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0);
    if ((int64_t)lkl_cd->disk_config.key <= 0)
    {
        sgxlkl_fail(
            "Unable to allocate memory for disk encryption key inside the "
            "enclave: %s\n",
            lkl_strerror((intptr_t)lkl_cd->disk_config.key));
    }
    memcpy(lkl_cd->disk_config.key, key_outside, lkl_cd->disk_config.key_len);

    err = crypt_activate_by_passphrase(
        cd,
        lkl_cd->crypt_name,
        CRYPT_ANY_SLOT,
        (char*)lkl_cd->disk_config.key,
        lkl_cd->disk_config.key_len,
        lkl_cd->readonly ? CRYPT_ACTIVATE_READONLY : 0);
    if (err == -1)
    {
        sgxlkl_fail("Unable to activate encrypted disk. Please ensure you "
                    "have provided the correct passphrase/keyfile!\n");
    }
    else if (err != 0)
    {
        sgxlkl_fail(
            "Unable to activate encrypted disk due to unknown error (error "
            "code: %d, message: %s)\n",
            err,
            strerror(-err));
    }

    crypt_free(cd);

    // The key is only needed during activation, so don't keep it around
    // afterwards and free up space.
    memset(lkl_cd->disk_config.key, 0, lkl_cd->disk_config.key_len);

    unsigned long munmap_ret;
    if ((munmap_ret = lkl_sys_munmap(
             (unsigned long)lkl_cd->disk_config.key,
             lkl_cd->disk_config.key_len)))
    {
        sgxlkl_fail(
            "Unable to unmap memory for disk encryption key: %s\n",
            lkl_strerror((int)munmap_ret));
    }
    lkl_cd->disk_config.key = NULL;
    lkl_cd->disk_config.key_len = 0;

    return 0;
}

static void* lkl_create_crypto_disk_thread(struct lkl_crypt_device* lkl_cd)
{
    int err;

    char* disk_path = lkl_cd->disk_path;

    struct crypt_device* cd;
    err = crypt_init(&cd, disk_path);
    if (err != 0)
        sgxlkl_fail("crypt_init(): %s (%d)\n", strerror(-err), err);

    // As we generate our own key and don't use a simple "password" we use
    // the minimal kdf settings possible.
    struct crypt_pbkdf_type pbkdf = {
        .type = "pbkdf2",
        .hash = "sha256",
        .iterations = 1000, // Minimum iterations that will be accepted.
        .time_ms = 1,
        .flags = CRYPT_PBKDF_NO_BENCHMARK};

    struct crypt_params_luks2 params = {
        .sector_size = 4096, .pbkdf = &pbkdf,
        // Temporarily disabled, see comment below.
        //.integrity = "hmac(sha512)"
    };
    // TODO uncomment/change integrity_key_size after moving to FLUKS
    // This reflects the integrity string defined above ("hmac(sha512)").
    // size_t integrity_key_size = 512 / 8;

    // FIXME adding integrity_key_size to the volume_key_size leads to "Bad
    // address" in crypt_hash_write()
    //  Output:
    //   # Setting PBKDF2 type key digest 0.
    //   [LKL SYSCALL ] [tid=58 ] writev 66      (1, 140491604915536, 2, 0, 0,
    //   0) = 36 [LKL SYSCALL ] [tid=58 ] read   63      (7, 140491604917056,
    //   32, 0, 0, 0) = 32 [LKL SYSCALL ] [tid=58 ] socket 198     (38, 5, 0, 0,
    //   0, 0) = 9 [LKL SYSCALL ] [tid=58 ] bind   200     (9, 140491604916048,
    //   88, 0, 0, 0) = 0 [LKL SYSCALL ] [tid=58 ] accept 202     (9, 0, 0, 0,
    //   0, 0) = 10 [LKL SYSCALL ] [tid=58 ] sendto 206     (10,
    //   140491566209008, 96, 32768, 0, 0) = -14 (Bad address) <--- ! [LKL
    //   SYSCALL ] [tid=58 ] close  57      (9, 0, 0, 0, 0, 0) = 0 [LKL SYSCALL
    //   ] [tid=58 ] close  57      (10, 0, 0, 0, 0, 0) = 0 [   SGX-LKL  ] Fail:
    //   crypt_format(): Invalid argument (-22)
    //
    // Not making the key larger but still enabling integrity avoids the above
    // error but then leads to error during disk activation:
    //   [    0.521978] device-mapper: table: 253:1: crypt: Error decoding and
    //   setting key"
    //
    // For now, we keep integrity disabled and re-enable it again after the move
    // to FLUKS, assuming the issue does not appear there.
    // size_t volume_key_size = 256 / 8 + integrity_key_size;

    size_t volume_key_size = 256 / 8;

    const char* cipher = "aes";
    const char* cipher_mode = "xts-plain64";

    err = crypt_format(
        cd,
        CRYPT_LUKS2,
        cipher,
        cipher_mode,
        NULL,
        NULL,
        volume_key_size,
        &params);
    if (err != 0)
        sgxlkl_fail("crypt_format(): %s (%d)\n", strerror(-err), err);

    // Key must be copied from userspace memory to LKL visible memory.
    uint8_t* key_outside = lkl_cd->disk_config.key;
    uint8_t* key_kernel = (uint8_t*)lkl_sys_mmap(
        NULL,
        lkl_cd->disk_config.key_len,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0);
    if ((int64_t)key_kernel <= 0)
        sgxlkl_fail(
            "Unable to allocate memory for disk encryption key inside the "
            "enclave: %s\n",
            lkl_strerror((intptr_t)key_kernel));
    memcpy(key_kernel, key_outside, lkl_cd->disk_config.key_len);

    err = crypt_keyslot_add_by_key(
        cd,
        CRYPT_ANY_SLOT,
        NULL,
        0,
        (char*)key_kernel,
        lkl_cd->disk_config.key_len,
        0);
    if (err != 0)
        sgxlkl_fail(
            "crypt_keyslot_add_by_key(): %s (%d)\n", strerror(-err), err);

    crypt_free(cd);

    unsigned long munmap_ret;
    if ((munmap_ret = lkl_sys_munmap(
             (unsigned long)key_kernel, lkl_cd->disk_config.key_len)))
        sgxlkl_fail(
            "Unable to unmap memory for disk encryption key: %s\n",
            lkl_strerror((int)munmap_ret));

    return 0;
}

static void* lkl_activate_verity_disk_thread(struct lkl_crypt_device* lkl_cd)
{
    int err;

    char* disk_path = lkl_cd->disk_path;

    struct crypt_device* cd;
    // cryptsetup!
    err = crypt_init(&cd, disk_path);
    if (err != 0)
    {
        sgxlkl_fail("crypt_init(): %s (%d)\n", strerror(err), err);
    }

    /*
     * The dm-verity Merkle tree that contains the hashes of all data blocks is
     * stored on the disk image following the actual data blocks. The offset
     * that signifies both the end of the data region as well as the start of
     * the hash region has to be provided to SGX-LKL.
     */
    struct crypt_params_verity verity_params = {
        .data_device = disk_path,
        .hash_device = disk_path,
        .hash_area_offset = lkl_cd->disk_config.roothash_offset,
        .data_size = lkl_cd->disk_config.roothash_offset /
                     512, // In blocks, divide by block size
        .data_block_size = 512,
        .hash_block_size = 512,
    };

    err = crypt_load(cd, CRYPT_VERITY, &verity_params);
    if (err != 0)
    {
        sgxlkl_fail("crypt_load(): %s (%d)\n", strerror(err), err);
    }

    uint8_t* volume_hash_bytes = NULL;
    ssize_t hash_size = crypt_get_volume_key_size(cd);
    if (hex_to_bytes(lkl_cd->disk_config.roothash, &volume_hash_bytes) !=
        hash_size)
    {
        sgxlkl_fail("Invalid root hash string specified!\n");
    }

    err = crypt_activate_by_volume_key(
        cd,
        lkl_cd->crypt_name,
        (char*)volume_hash_bytes,
        32,
        lkl_cd->readonly ? CRYPT_ACTIVATE_READONLY : 0);
    if (err != 0)
    {
        sgxlkl_fail(
            "crypt_activate_by_volume_key(): %s (%d)\n", strerror(err), err);
    }

    crypt_free(cd);
    free(volume_hash_bytes);

    return NULL;
}

static void lkl_run_in_kernel_stack(void* (*start_routine)(void*), void* arg)
{
    int err;

    /*
     * We need to pivot to a stack which is inside LKL's known memory mappings
     * otherwise get_user_pages will not manage to find the mapping, and will
     * fail.
     *
     * Buffers passed to the kernel via the crypto API need to be allocated
     * on this stack, or on heap pages allocated via lkl_sys_mmap.
     */
    const int stack_size = 32 * 1024;

    void* addr = lkl_sys_mmap(
        NULL,
        stack_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0);
    if ((intptr_t)addr < 0)
    {
        sgxlkl_fail("lkl_sys_mmap failed\n");
    }

    pthread_t pt;
    pthread_attr_t ptattr;
    pthread_attr_init(&ptattr);
    pthread_attr_setstack(&ptattr, addr, stack_size);
    err = pthread_create(&pt, &ptattr, start_routine, arg);
    if (err < 0)
    {
        sgxlkl_fail("pthread_create()=%s (%d)\n", strerror(err), err);
    }

    err = pthread_join(pt, NULL);
    if (err < 0)
    {
        sgxlkl_fail("pthread_join()=%s (%d)\n", strerror(err), err);
    }
}

static bool is_encrypted_cfg(disk_config_t* cfg)
{
    return cfg->key || cfg->key_id || cfg->fresh_key;
}

static void lkl_mount_virtual()
{
    lkl_mount_devtmpfs("/dev");
    lkl_prepare_rootfs("/proc", 0700);
    lkl_mount_procfs();
    lkl_prepare_rootfs("/sys", 0700);
    lkl_mount_sysfs();
    lkl_prepare_rootfs("/run", 0700);
    lkl_mount_runfs();
    lkl_mknods();
}

static void lkl_mount_disk(
    disk_config_t* disk,
    char device,
    const char* mnt_point,
    size_t disk_index)
{
    char dev_str_raw[] = {"/dev/vdX"};
    char dev_str_enc[] = {"/dev/mapper/cryptX"};
    char dev_str_verity[] = {"/dev/mapper/verityX"};
    const size_t offset_dev_str_crypt_name = sizeof "/dev/mapper/" - 1;

    dev_str_raw[sizeof dev_str_raw - 2] = device;
    char* dev_str = dev_str_raw;

    SGXLKL_VERBOSE(
        "lkl_mount_disk(dev=\"%s\", mnt=\"%s\", ro=%i)\n",
        dev_str,
        mnt_point,
        disk->readonly);

    struct lkl_crypt_device lkl_cd;
    lkl_cd.disk_path = dev_str;
    lkl_cd.readonly = disk->readonly;
    lkl_cd.disk_config = *disk;

    if (disk->create && disk->fresh_key)
    {
        disk->key_len = CREATED_DISK_KEY_LENGTH / 8;
        SGXLKL_VERBOSE("Generating random disk encryption key\n");
        disk->key = malloc(disk->key_len);
        if (disk->key == NULL)
            sgxlkl_fail("Could not allocate memory for disk encryption key\n");
        for (size_t i = 0; i < disk->key_len; i++)
            /* TODO: keys should be set up prior to reaching this function.
             * Also, if we need fresh keys at all, they should be generated
             * properly, e.g. by using the DRNG instructions or mbedTLS for RSA
             * keys. */
            disk->key[i] = rand();
    }

    int lkl_trace_lkl_syscall_bak = sgxlkl_trace_lkl_syscall;
    int lkl_trace_internal_syscall_bak = sgxlkl_trace_internal_syscall;

    if ((sgxlkl_trace_lkl_syscall || sgxlkl_trace_internal_syscall) &&
        (disk->roothash || is_encrypted_cfg(disk)))
    {
        sgxlkl_trace_lkl_syscall = 0;
        sgxlkl_trace_internal_syscall = 0;
        SGXLKL_VERBOSE("Disk encryption/integrity enabled: Temporarily "
                       "disabling tracing to reduce noise.\n");
    }

    if (disk->roothash != NULL)
    {
        SGXLKL_VERBOSE("Activating verity disk\n");
        dev_str_verity[sizeof dev_str_verity - 2] = device;
        lkl_cd.crypt_name = dev_str_verity + offset_dev_str_crypt_name;
        lkl_run_in_kernel_stack(
            (void* (*)(void*)) & lkl_activate_verity_disk_thread,
            (void*)&lkl_cd);

        // We now want to mount the verified volume
        dev_str = dev_str_verity;
        lkl_cd.disk_path = dev_str_verity;
        // dm-verity is read only
        disk->readonly = 1;
        lkl_cd.readonly = 1;
    }

    if (is_encrypted_cfg(disk))
    {
        dev_str_enc[sizeof dev_str_enc - 2] = device;
        lkl_cd.crypt_name = dev_str_enc + offset_dev_str_crypt_name;
        if (disk->create)
        {
            SGXLKL_VERBOSE("Creating empty crypto disk\n");
            lkl_run_in_kernel_stack(
                (void* (*)(void*)) & lkl_create_crypto_disk_thread,
                (void*)&lkl_cd);
        }

        SGXLKL_VERBOSE("Activating crypto disk\n");
        lkl_run_in_kernel_stack(
            (void* (*)(void*)) & lkl_activate_crypto_disk_thread,
            (void*)&lkl_cd);

        // We now want to mount the decrypted volume
        dev_str = dev_str_enc;
    }

    if ((lkl_trace_lkl_syscall_bak && !sgxlkl_trace_lkl_syscall) ||
        (lkl_trace_internal_syscall_bak && !sgxlkl_trace_internal_syscall))
    {
        SGXLKL_VERBOSE(
            "Disk encryption/integrity enabled: Re-enabling tracing.\n");
        sgxlkl_trace_lkl_syscall = lkl_trace_lkl_syscall_bak;
        sgxlkl_trace_internal_syscall = lkl_trace_internal_syscall_bak;
    }

    if (disk->create)
    {
        size_t fs_size = disk->size;

        if (is_encrypted_cfg(disk))
        {
            SGXLKL_VERBOSE(
                "Assuming a disk encryption/integrity overhead of %d %%\n",
                (int)(CREATED_DISK_ENCRYPTION_OVERHEAD * 100));
            fs_size = fs_size * (1 - CREATED_DISK_ENCRYPTION_OVERHEAD);
            // align to block size
            fs_size = (fs_size + CREATED_DISK_EXT4_BLOCK_SIZE - 1) /
                      CREATED_DISK_EXT4_BLOCK_SIZE *
                      CREATED_DISK_EXT4_BLOCK_SIZE;
        }

        int result;
        unsigned long long num_blocks = fs_size / CREATED_DISK_EXT4_BLOCK_SIZE;
        SGXLKL_VERBOSE("Creating ext4 filesystem of size %ld\n", fs_size);
        SGXLKL_VERBOSE(
            "make_ext4_dev(block_size=\"%d\", num_blocks=\"%lld\")\n",
            CREATED_DISK_EXT4_BLOCK_SIZE,
            num_blocks);
        result =
            make_ext4_dev(dev_str, CREATED_DISK_EXT4_BLOCK_SIZE, num_blocks);
        if (result != 0)
            sgxlkl_fail("make_ext4_dev()=%s\n", result);
    }

    const int err = lkl_mount_blockdev(
        dev_str, mnt_point, "ext4", disk->readonly ? LKL_MS_RDONLY : 0, NULL);
    if (err < 0)
        sgxlkl_fail("lkl_mount_blockdev()=%s (%d)\n", lkl_strerror(err), err);

    sgxlkl_enclave_state.disk_state[disk_index].mounted = true;
}

static void lkl_mount_root_disk(
    const sgxlkl_enclave_root_config_t* root,
    size_t disk_index)
{
    int err = 0;
    char mnt_point[] = "/mnt/vda";
    char new_dev_str[] = "/mnt/vda/dev/";

    // If any byte of disk_dm_verity_root_hash is not 0xff, the verification
    // is run to compare disk_dm_verity_root_hash against disk->roothash.
    // We assume no valid root hash would be all 0xff.
    for (size_t i = 0; i < sizeof(disk_dm_verity_root_hash); ++i)
    {
        if (disk_dm_verity_root_hash[i] != 0xff)
        {
            SGXLKL_VERBOSE("Verifing root hash with embedded one.\n");
            char buf[2 * sizeof(disk_dm_verity_root_hash) + 1];
            if (bytes_to_hex(
                    buf,
                    sizeof(buf),
                    disk_dm_verity_root_hash,
                    sizeof(disk_dm_verity_root_hash)) == NULL)
            {
                sgxlkl_fail("bytes_to_hex() failed.\n");
            }
            if (root->roothash == NULL || strcmp(root->roothash, buf) != 0)
            {
                sgxlkl_fail(
                    "The root hash does not match with embedded one.\n");
            }
            break;
        }
    }

    disk_config_t cfg = {.create = false,
                         .destination = "/",
                         .key_len = root->key_len,
                         .key = root->key,
                         .key_id = root->key_id,
                         .fresh_key = false,
                         .readonly = root->readonly,
                         .roothash = root->roothash,
                         .roothash_offset = root->roothash_offset,
                         .size = 0,
                         .overlay = root->overlay};
    lkl_mount_disk(&cfg, 'a', mnt_point, 0);

    if (root->overlay)
    {
        SGXLKL_VERBOSE("Creating writable in-memory overlay for rootfs.\n");
        const char mnt_point_overlay[] = "/mnt/oda";
        const char mnt_point_overlay_upper[] = "/mnt/oda-upper";
        const char overlay_upper_dir[] = "/mnt/oda-upper/upper";
        const char overlay_work_dir[] = "/mnt/oda-upper/work";
        lkl_prepare_rootfs(mnt_point_overlay_upper, 0700);
        lkl_mount_overlay_tmpfs(mnt_point_overlay_upper);
        lkl_prepare_rootfs(overlay_upper_dir, 0700);
        lkl_prepare_rootfs(overlay_work_dir, 0700);
        lkl_prepare_rootfs(mnt_point_overlay, 0700);
        lkl_mount_overlayfs(
            mnt_point, overlay_upper_dir, overlay_work_dir, mnt_point_overlay);
        strcpy(mnt_point, mnt_point_overlay);
        strcpy(new_dev_str, "/mnt/oda/dev/");
    }

    /* set up /dev in the new root */
    lkl_prepare_rootfs(new_dev_str, 0700);
    lkl_mount_devtmpfs(new_dev_str);
    lkl_copy_blkdev_nodes("/dev/", new_dev_str);

    /* clean up */
    lkl_sys_umount("/proc", 0);
    lkl_sys_umount("/sys", 0);
    lkl_sys_umount("/run", 0);
    lkl_sys_umount("/dev", 0);

    /* pivot */
    err = lkl_sys_chroot(mnt_point);
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_chroot(%s): %s\n", mnt_point, lkl_strerror(err));
    }

    err = lkl_sys_chdir("/");
    if (err != 0)
    {
        sgxlkl_fail("lkl_sys_chdir(%s): %s\n", mnt_point, lkl_strerror(err));
    }

    lkl_prepare_rootfs("/dev", 0700);
    lkl_prepare_rootfs("/dev/shm", 0777);
    lkl_prepare_rootfs("/mnt", 0700);
    lkl_prepare_rootfs("/tmp", 0777);
    lkl_prepare_rootfs("/sys", 0700);
    lkl_prepare_rootfs("/run", 0700);
    lkl_prepare_rootfs("/proc", 0700);
    lkl_mount_shmtmpfs();
    lkl_mount_tmpfs();
    lkl_mount_mntfs();
    lkl_mount_sysfs();
    lkl_mount_runfs();
    lkl_mount_procfs();
}

void lkl_mount_disks(
    const sgxlkl_enclave_root_config_t* root,
    const sgxlkl_enclave_mount_config_t* mounts,
    size_t num_mounts,
    const char* cwd)
{
#ifdef DEBUG
    if (sgxlkl_trace_disk)
        crypt_set_debug_level(CRYPT_LOG_DEBUG);
#endif

    if (!root)
        sgxlkl_fail("No root disk provided. Aborting...\n");

    lkl_add_disks(root, mounts, num_mounts);

    lkl_mount_root_disk(root, 0);

    for (size_t mnt_idx = 0; mnt_idx < num_mounts; mnt_idx++)
    {
        size_t dsk_idx = mnt_idx + 1;

        SGXLKL_ASSERT(strcmp(mounts[mnt_idx].destination, "/") != 0);

        // We assign dev paths from /dev/vda to /dev/vdz, assuming we won't need
        // support for more than 26 disks.
        if ('a' + dsk_idx > 'z')
        {
            sgxlkl_warn(
                "Too many disks (maximum is 26). Failed to mount disk %d at "
                "%s.\n",
                dsk_idx,
                mounts[mnt_idx].destination);
            // Adjust number to number of mounted disks.
            num_mounts = 25;
            return;
        }
        disk_config_t cfg = {.create = mounts[mnt_idx].create,
                             .destination = mounts[mnt_idx].destination,
                             .key_len = mounts[mnt_idx].key_len,
                             .key = mounts[mnt_idx].key,
                             .key_id = mounts[mnt_idx].key_id,
                             .fresh_key = mounts[mnt_idx].fresh_key,
                             .readonly = mounts[mnt_idx].readonly,
                             .roothash = mounts[mnt_idx].roothash,
                             .roothash_offset = mounts[mnt_idx].roothash_offset,
                             .size = mounts[mnt_idx].size,
                             .overlay = false};
        lkl_mount_disk(&cfg, 'a' + dsk_idx, cfg.destination, dsk_idx);
    }

    if (cwd)
    {
        SGXLKL_VERBOSE("Set working directory: %s\n", cwd);
        int ret = lkl_sys_chdir(cwd);
        if (ret != 0)
        {
            sgxlkl_fail(
                "lkl_sys_chdir(%s) failed: ret=%i error=\"%s\"\n",
                cwd,
                ret,
                lkl_strerror(ret));
        }
    }
}

static uint32_t _parse_ip4(const char* str)
{
    struct in_addr ia_tmp = {0};
    if (inet_pton(AF_INET, str, &ia_tmp) != 1)
        sgxlkl_fail("Invalid IPv4 address: %s\n", str);
    return ia_tmp.s_addr;
}

void lkl_poststart_net(int net_dev_id)
{
    const sgxlkl_enclave_config_t* cfg = sgxlkl_enclave_state.config;
    int res = 0;
    if (net_dev_id >= 0)
    {
        int ifidx = lkl_netdev_get_ifindex(net_dev_id);
        uint32_t ip4 = _parse_ip4(cfg->net_ip4);
        res = lkl_if_set_ipv4(ifidx, ip4, atoi(cfg->net_mask4));
        if (res < 0)
        {
            sgxlkl_fail("lkl_if_set_ipv4(): %s\n", lkl_strerror(res));
        }
        res = lkl_if_up(ifidx);
        if (res < 0)
        {
            sgxlkl_fail("lkl_if_up(eth0): %s\n", lkl_strerror(res));
        }
        if (cfg->net_gw4 > 0)
        {
            uint32_t gw4 = _parse_ip4(cfg->net_gw4);
            res = lkl_set_ipv4_gateway(gw4);
            if (res < 0)
            {
                sgxlkl_fail("lkl_set_ipv4_gateway(): %s\n", lkl_strerror(res));
            }
        }

        if (sgxlkl_mtu)
        {
            lkl_if_set_mtu(ifidx, sgxlkl_mtu);
        }
    }
    res = lkl_if_up(1);
    if (res < 0)
    {
        sgxlkl_fail("lkl_if_up(1=lo): %s\n", lkl_strerror(res));
    }
}

static void do_sysctl()
{
    const sgxlkl_enclave_config_t* cfg = sgxlkl_enclave_state.config;

    if (!cfg->sysctl)
        return;

    char* sysctl_all = strdup(cfg->sysctl);
    char* sysctl = sysctl_all;
    while (*sysctl)
    {
        while (*sysctl == ' ')
            sysctl++;

        char* path = sysctl;
        char* val = strchrnul(path, '=');
        if (!*val)
        {
            sgxlkl_warn(
                "Failed to set sysctl config \"%s\", key and value not "
                "seperated by '='.\n",
                path);
            break;
        }

        *val = '\0';
        val++;
        char* val_end = strchrnul(val, ';');
        if (*val_end)
        {
            *val_end = '\0';
            val_end++;
        }
        sysctl = val_end;

        SGXLKL_VERBOSE("Setting sysctl config: %s=%s\n", path, val);
        if (lkl_sysctl(path, val))
        {
            sgxlkl_warn("Failed to set sysctl config %s=%s\n", path, val);
            break;
        }
    }

    free(sysctl_all);
}

static void init_wireguard()
{
    const sgxlkl_enclave_config_t* cfg = sgxlkl_enclave_state.config;

    wg_device new_device = {
        .name = "wg0",
        .listen_port = cfg->wg.listen_port,
        .flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT,
        .first_peer = NULL,
        .last_peer = NULL};

    char* wg_key_b64 = cfg->wg.key;
    if (wg_key_b64)
    {
        wg_key_from_base64(new_device.private_key, wg_key_b64);
    }
    else
    {
        wg_generate_private_key(new_device.private_key);
    }

    wgu_add_peers(&new_device, cfg->wg.peers, cfg->wg.num_peers, 0);

    if (wg_add_device(new_device.name) < 0)
    {
        perror("Unable to add wireguard device");
        return;
    }

    if (wg_set_device(&new_device) < 0)
    {
        perror("Unable to set wireguard device");
        return;
    }

    int wgifindex = lkl_ifname_to_ifindex(new_device.name);
    lkl_if_set_ipv4(wgifindex, _parse_ip4(cfg->wg.ip), 24);
    lkl_if_up(wgifindex);
}

static void init_random()
{
    struct rand_pool_info* pool_info = 0;
    FILE* f;
    int fd = 0;

    SGXLKL_VERBOSE("Adding entropy to entropy pool\n");

    char buf[8] = {0};
    f = fopen("/proc/sys/kernel/random/poolsize", "r");
    if (!f)
        goto err;
    if (fgets(buf, 8, f) == NULL)
        goto err;
    // /proc/sys/kernel/random/poolsize for kernel 2.6+ contains pool size in
    // bits, divide by 8 for number of bytes.
    int poolsize = atoi(buf) / 8;

    // To be on the safe side, add entropy equivalent to the pool size.
    pool_info = (struct rand_pool_info*)malloc(sizeof(pool_info) + poolsize);
    if (!pool_info)
        goto err;

    pool_info->entropy_count = poolsize * 8;
    pool_info->buf_size = poolsize;

    uint64_t* entropy_buf = (uint64_t*)pool_info->buf;
    for (int i = 0; i < poolsize / 8; i++)
    {
        // TODO Use intrinsics
        // if (!_rdrand64_step(&entropy_buf[i]))
        //    goto err;
        register uint64_t rd;
        __asm__ volatile("rdrand %0;" : "=r"(rd));
        entropy_buf[i] = rd;
    }

    fd = open("/dev/random", O_RDONLY);
    if (ioctl(fd, RNDADDENTROPY, pool_info) == -1)
        goto err;

    goto out;
err:
    sgxlkl_warn("Failed to add entropy to entropy pool.\n");
out:
    if (f)
        fclose(f);
    if (fd)
        close(fd);
    if (pool_info)
        free(pool_info);
}

/* Get the difference between end and start. If end is before start,
 * returns {0, 0}
 */
struct timespec timespec_diff(struct timespec end, struct timespec start)
{
    struct timespec diff = {0, 0};

    if (start.tv_sec <= end.tv_sec ||
        (start.tv_sec == end.tv_sec && start.tv_nsec < end.tv_nsec))
    {
        diff.tv_sec = end.tv_sec - start.tv_sec;
        if (start.tv_nsec > end.tv_nsec)
        {
            diff.tv_sec--;
        }

        diff.tv_nsec = (1000000000 + end.tv_nsec - start.tv_nsec) % 1000000000;
    }

    return diff;
}

#ifdef DEBUG
static void display_mount_table()
{
    int fd, ret;
    char buf[1024];

    fd = lkl_sys_open("/proc/mounts", O_RDONLY, 0);
    if (fd < 0)
    {
        SGXLKL_VERBOSE("/proc/mounts cannot be accessed\n");
        return;
    }

    SGXLKL_VERBOSE("========= /proc/mounts ===========\n");
    while ((ret = lkl_sys_read(fd, buf, 1023)) > 0)
    {
        buf[ret] = '\0';
        SGXLKL_VERBOSE_RAW("%s", buf);
    }
    SGXLKL_VERBOSE("==================================\n");

    ret = lkl_sys_close(fd);
    if (ret != 0)
    {
        sgxlkl_fail("Could not close file descriptor for /proc/mounts\n");
    }
}
#endif

/* Semaphore used to block LKL termination thread */
static struct lkl_sem* termination_sem;

/* Record whether we are terminmating LKL */
static _Atomic(bool) _is_lkl_terminating = false;

/* Function to carry out the shutdown sequence */
static void* lkl_termination_thread(void* args)
{
    SGXLKL_VERBOSE("enter\n");

    /*
     * We need to issue a system call here to ensure that this applicaiton
     * thread is mapped to an LKL host thread. This way, no new kernel thread
     * will be created when we are actually shutting down.
     */
    long pid __attribute__((unused)) = lkl_sys_getpid();
    SGXLKL_VERBOSE(
        "Performed LKL syscall to get host task allocated (pid=%li)\n", pid);
    SGXLKL_ASSERT(pid);

    /* Block on semaphore until shutdown */
    sgxlkl_host_ops.sem_down(termination_sem);

    SGXLKL_VERBOSE("termination thread unblocked\n");

    /* Expose exit status based on enclave config */
    const sgxlkl_enclave_config_t* cfg = sgxlkl_enclave_state.config;
    switch (cfg->exit_status)
    {
        case EXIT_STATUS_FULL:
            /* do nothing */
            break;
        case EXIT_STATUS_BINARY:
            sgxlkl_enclave_state.exit_status =
                sgxlkl_enclave_state.exit_status == 0 ? 0 : 1;
            break;
        case EXIT_STATUS_NONE:
            sgxlkl_enclave_state.exit_status = 0;
            break;
        default:
            SGXLKL_ASSERT(false);
    }

    if (getenv_bool("SGXLKL_PRINT_APP_RUNTIME", 0))
    {
        struct timespec endtime, runtime;
        clock_gettime(CLOCK_MONOTONIC, &endtime);
        runtime = timespec_diff(endtime, sgxlkl_app_starttime);
        sgxlkl_info(
            "Application runtime: %lld.%.9lds\n",
            runtime.tv_sec,
            runtime.tv_nsec);
    }

    // Switch back to root so we can unmount all filesystems
    SGXLKL_VERBOSE("calling lkl_sys_chdir(/)\n");
    int ret = lkl_sys_chdir("/");
    if (ret != 0)
    {
        sgxlkl_warn(
            "lkl_sys_chdir(\"/\") failed: ret=%i error=\"%s\"\n",
            ret,
            lkl_strerror(ret));
    }

#ifdef DEBUG
    display_mount_table();
#endif

    // Unmount mounts
    long res;
    for (int i = sgxlkl_enclave_state.num_disk_state - 1; i > 0; --i)
    {
        if (!sgxlkl_enclave_state.disk_state[i].mounted)
            continue;

        sgxlkl_enclave_mount_config_t* disk_i = &cfg->mounts[i];
        SGXLKL_VERBOSE(
            "calling lkl_umount_timeout(\"%s\", 0, %i)\n",
            disk_i->destination,
            UMOUNT_DISK_TIMEOUT);
        res = lkl_umount_timeout(disk_i->destination, 0, UMOUNT_DISK_TIMEOUT);
        if (res < 0)
        {
            sgxlkl_warn(
                "Could not unmount disk %d, %s\n", i, lkl_strerror(res));
        }

        if (!cfg->root.readonly)
        {
            // Not really necessary for mounts in /mnt since /mnt is
            // mounted as tmpfs itself, but it is also possible to mount
            // secondary images at any place in the root file system,
            // including persistent storage, if the root file system is
            // writeable. For simplicity, remove all mount points here.
            res = lkl_sys_rmdir(disk_i->destination);
            if (res < 0)
            {
                sgxlkl_warn(
                    "Could not remove mount point %s\n",
                    disk_i->destination,
                    lkl_strerror(res));
            }
        }
    }

#ifdef DEBUG
    display_mount_table();
#endif

    /* Unmount root.
     * We are calling umount with the MNT_DETACH flag for the root
     * file system, otherwise the call fails to unmount the file
     * system or sometimes blocks indefinitely. (We should still
     * check that the file system was unmounted cleanly.) */
    SGXLKL_VERBOSE(
        "calling lkl_umount_timeout(\"/\", MNT_DETACH, %i)\n",
        UMOUNT_DISK_TIMEOUT);
    res = lkl_umount_timeout("/", MNT_DETACH, UMOUNT_DISK_TIMEOUT);
    if (res < 0)
        sgxlkl_warn("Could not unmount root disk, %s\n", lkl_strerror(res));

    SGXLKL_VERBOSE("calling lkl_virtio_netdev_remove()\n");
    lkl_virtio_netdev_remove();

    SGXLKL_VERBOSE("calling lkl_sys_halt()\n");
    res = lkl_sys_halt();
    if (res < 0)
    {
        sgxlkl_fail("LKL halt, %s\n", lkl_strerror(res));
    }

    /* Notify host about the guest shutdown */
    sgxlkl_host_shutdown_notification();

    /* Set termination flag to notify lthread scheduler to bail out. */
    lthread_notify_completion();

    lthread_detach2(lthread_self());
    SGXLKL_VERBOSE("lthread_detach2() done\n");

    /* Free the shutdown semaphore late in the shutdown sequence */
    sgxlkl_host_ops.sem_free(termination_sem);

    sgxlkl_free_enclave_state();

    lthread_exit(NULL);
}

/* Create the LKL termination thread */
static void create_lkl_termination_thread()
{
    SGXLKL_VERBOSE("enter\n");

    termination_sem = sgxlkl_host_ops.sem_alloc(0);

    struct lthread* lt;
    int ret = lthread_create(&lt, NULL, lkl_termination_thread, NULL);
    if (ret != 0)
    {
        sgxlkl_fail("Could not create lkl_termination thread (ref=%i)\n", ret);
    }
}

/* Terminate LKL with a given exit status */
void lkl_terminate(int exit_status)
{
    /*
     * We only want to trigger the shutdown once. Since we are shutting down
     * the applicaton and the kernel, many other threads will be exiting now.
     */
    if (!_is_lkl_terminating)
    {
        SGXLKL_VERBOSE("terminating LKL (exit_status=%i)\n", exit_status);
        _is_lkl_terminating = true;
        sgxlkl_enclave_state.exit_status = exit_status;
        /* Wake up LKL termination thread to carry out the work. */
        sgxlkl_host_ops.sem_up(termination_sem);
    }
}

/* Return if LKL is currently terminating */
bool is_lkl_terminating()
{
    return _is_lkl_terminating;
}

static void init_enclave_clock()
{
    sgxlkl_shared_memory_t* shm = &sgxlkl_enclave_state.shared_memory;

    SGXLKL_VERBOSE("Setting enclave realtime clock\n");

    if (oe_is_within_enclave(shm->timer_dev_mem, sizeof(struct timer_dev)))
    {
        sgxlkl_fail(
            "timer_dev memory isn't outside of the enclave. Aborting.\n");
    }

    struct timer_dev* t = shm->timer_dev_mem;
    struct lkl_timespec start_time;
    start_time.tv_sec = t->init_walltime_sec;
    start_time.tv_nsec = t->init_walltime_nsec;
    int ret = lkl_sys_clock_settime(LKL_CLOCK_REALTIME, (void*)&start_time);
    if (ret != 0)
    {
        sgxlkl_fail(
            "lkl_sys_clock_settime(\"/\") failed: ret=%i error=\"%s\"\n",
            ret,
            lkl_strerror(ret));
    }
}

void lkl_start_init()
{
    size_t i;

    sgxlkl_shared_memory_t* shm = &sgxlkl_enclave_state.shared_memory;
    const sgxlkl_enclave_config_t* cfg = sgxlkl_enclave_state.config;

    // Provide LKL host ops and virtio block device ops
    lkl_host_ops = sgxlkl_host_ops;

    // TODO Make tracing options configurable via SGX-LKL config file.
    if (getenv_bool("SGXLKL_TRACE_SYSCALL", 0))
    {
        sgxlkl_trace_lkl_syscall = 1;
        sgxlkl_trace_internal_syscall = 1;
        sgxlkl_trace_ignored_syscall = 1;
        sgxlkl_trace_unsupported_syscall = 1;
    }

    if (getenv_bool("SGXLKL_TRACE_LKL_SYSCALL", 0))
        sgxlkl_trace_lkl_syscall = 1;

    if (getenv_bool("SGXLKL_TRACE_INTERNAL_SYSCALL", 0))
        sgxlkl_trace_internal_syscall = 1;

    if (getenv_bool("SGXLKL_TRACE_IGNORED_SYSCALL", 0))
        sgxlkl_trace_ignored_syscall = 1;

    if (getenv_bool("SGXLKL_TRACE_UNSUPPORTED_SYSCALL", 0))
        sgxlkl_trace_unsupported_syscall = 1;

    if (getenv_bool("SGXLKL_TRACE_REDIRECT_SYSCALL", 0))
        sgxlkl_trace_redirect_syscall = 1;

    if (getenv_bool("SGXLKL_TRACE_MMAP", 0))
        sgxlkl_trace_mmap = 1;

    if (getenv_bool("SGXLKL_TRACE_SIGNAL", 0))
        sgxlkl_trace_signal = 1;

    if (getenv_bool("SGXLKL_TRACE_THREAD", 0))
        sgxlkl_trace_thread = 1;

    if (getenv_bool("SGXLKL_TRACE_DISK", 0))
        sgxlkl_trace_disk = 1;

    if (cfg->hostnet)
        sgxlkl_use_host_network = 1;

    SGXLKL_VERBOSE("calling register_lkl_syscall_overrides()\n");
    register_lkl_syscall_overrides();

    sgxlkl_mtu = cfg->tap_mtu;

    SGXLKL_VERBOSE("calling initialize_enclave_event_channel()\n");
    initialize_enclave_event_channel(shm->enc_dev_config, shm->evt_channel_num);

    // Register console device
    lkl_virtio_console_add(shm->virtio_console_mem);

    // Register network tap if given one
    int net_dev_id = -1;
    if (shm->virtio_net_dev_mem)
        net_dev_id = lkl_virtio_netdev_add(shm->virtio_net_dev_mem);

    /* Prepare bootargs to boot lkl kernel */
    char bootargs[BOOTARGS_LEN] = {0};

    /* Each bootargs options are seperated using blank space. so 1 is added */
    int flen = strlen(BOOTARGS_CONSOLE_OPTION) + 1;
    if (!cfg->kernel_verbose)
        flen += strlen(BOOTARGS_QUIET_OPTION) + 1;

    if (strlen(cfg->kernel_cmd) > BOOTARGS_LEN - flen)
        sgxlkl_fail(
            "LKL boot cmdline too long : %s len = %d",
            cfg->kernel_cmd,
            strlen(cfg->kernel_cmd));

    /* Check that the supplied bootargs do not cause buffer overflow */
    if (!cfg->kernel_verbose)
    {
        oe_snprintf(
            bootargs,
            sizeof(bootargs),
            "%s %s %s",
            cfg->kernel_cmd,
            BOOTARGS_CONSOLE_OPTION,
            "quiet");
    }
    else
    {
        oe_snprintf(
            bootargs,
            sizeof(bootargs),
            "%s %s",
            cfg->kernel_cmd,
            BOOTARGS_CONSOLE_OPTION);
    }

    // Start kernel threads (synchronous, doesn't return before kernel is ready)
    const char* lkl_cmdline = bootargs;
    SGXLKL_VERBOSE("kernel command line: \'%s\'\n", lkl_cmdline);

    SGXLKL_VERBOSE(
        "Disk 0: Disk encryption: %s\n",
        (cfg->root.key || cfg->root.key_id ? "yes" : "no"));
    SGXLKL_VERBOSE(
        "Disk 0: Disk is writable: %s\n", (!cfg->root.readonly ? "yes" : "no"));

    size_t num_mounts = cfg->num_mounts;
    for (i = 0; i < num_mounts; ++i)
    {
        SGXLKL_VERBOSE(
            "Disk %zu: Disk encryption: %s\n",
            i + 1,
            (is_encrypted(&cfg->mounts[i]) ? "yes" : "no"));
        SGXLKL_VERBOSE(
            "Disk %zu: Disk is writable: %s\n",
            i + 1,
            (!cfg->mounts[i].readonly ? "yes" : "no"));
    }

    /* Setup bounce buffer for virtio */
    if (sgxlkl_enclave_state.config->swiotlb)
    {
        /* validate bounce buffer memory before setting it up */
        if (!oe_is_within_enclave(
                shm->virtio_swiotlb, shm->virtio_swiotlb_size))
        {
            lkl_initialize_swiotlb(
                shm->virtio_swiotlb, shm->virtio_swiotlb_size);
        }
        else
        {
            sgxlkl_fail("Bounce buffer memory not valid, Aborting\n");
        }
    }

    SGXLKL_VERBOSE("lkl_start_kernel() called\n");
    long res = lkl_start_kernel(&lkl_host_ops, lkl_cmdline);
    if (res < 0)
    {
        sgxlkl_fail("Could not start LKL kernel, %s\n", lkl_strerror(res));
    }
    SGXLKL_VERBOSE("lkl_start_kernel() finished\n");

    SGXLKL_VERBOSE("creating LKL termination thread\n");
    create_lkl_termination_thread();

    // Now that our kernel is ready to handle syscalls, mount root
    SGXLKL_VERBOSE("calling lkl_mount_virtual()\n");
    lkl_mount_virtual();

    SGXLKL_VERBOSE("calling init_random()\n");
    init_random();

    init_enclave_clock();

    // Sysctl
    do_sysctl();

    // Set interface status/IP/routes
    if (!sgxlkl_use_host_network)
        lkl_poststart_net(net_dev_id);

    // Set up wireguard
    init_wireguard();

    // Set hostname (provided through SGXLKL_HOSTNAME)
    sethostname(cfg->hostname, strlen(cfg->hostname));
}

extern inline int lkl_access_ok(unsigned long addr, unsigned long size)
{
    /* Set default state as access_ok */
    int ret = 1;

    /* size 0 access should not be treated as invalid access */
    if (!size)
        return ret;

    ret = oe_is_within_enclave((void*)addr, size);
    if (!ret)
    {
        sgxlkl_fail("lkl_access_check failed: %p\n", (void*)addr);
    }
    return ret;
}
