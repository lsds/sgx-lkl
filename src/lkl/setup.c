/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <lkl_host.h>

#include "lkl/disk.h"
#include "lkl/posix-host.h"
#include "lkl/setup.h"
#include "lkl/virtio_net.h"
#include "sgx_enclave_config.h"
#include "sgxlkl_debug.h"
#include "sgxlkl_util.h"
#include "libcryptsetup.h"
#include "libdevmapper.h"
#include "pthread.h"


#define BIT(x) (1ULL << x)

#define UMOUNT_DISK_TIMEOUT 2000

int sethostname(const char *, size_t);

int sgxlkl_trace_lkl_syscall = 0;
int sgxlkl_trace_internal_syscall = 0;
int sgxlkl_trace_mmap = 0;
int sgxlkl_trace_thread = 0;
int sgxlkl_use_host_network = 0;
int sgxlkl_use_tap_offloading = 0;
int sgxlkl_mmap_file_support = 0;
int sgxlkl_mtu = 0;

extern struct timespec sgxlkl_app_starttime;

size_t num_disks = 0;
struct enclave_disk_config *disks;

static void lkl_prestart_disks(struct enclave_disk_config *disks, size_t num_disks) {
    for (size_t i = 0; i < num_disks; ++i) {
        /* Set ops to NULL to use platform default ops */
        struct lkl_disk lkl_disk;
        lkl_disk.ops = NULL;
        lkl_disk.fd = disks[i].fd;
        int disk_dev_id = lkl_disk_add(&lkl_disk);
        if (disk_dev_id < 0) {
            fprintf(stderr, "Error: unable to register disk %d, %s\n", i, lkl_strerror(disk_dev_id));
            exit(EXIT_FAILURE);
        }
    }
}

static int lkl_prestart_net(enclave_config_t* encl) {
    struct lkl_netdev *netdev = sgxlkl_register_netdev_fd(encl->net_fd);
    if (netdev == NULL) {
        fprintf(stderr, "Error: unable to register netdev\n");
        exit(2);
    }
    char mac[6] = { 0xCA, 0xFE, 0x00, 0x00, 0x00, 0x01 };
    struct lkl_netdev_args netdev_args = {
        .mac = mac,
        .offload= 0,
    };

    if (sgxlkl_use_tap_offloading) {
        netdev->has_vnet_hdr = 1;
        // Host and guest can handle partial checksums
        netdev_args.offload = BIT(LKL_VIRTIO_NET_F_CSUM) | BIT(LKL_VIRTIO_NET_F_GUEST_CSUM);
        // Host and guest can handle TSOv4
        netdev_args.offload |= BIT(LKL_VIRTIO_NET_F_HOST_TSO4) | BIT(LKL_VIRTIO_NET_F_GUEST_TSO4);
        // Host and guest can handle TSOv6
        netdev_args.offload |= BIT(LKL_VIRTIO_NET_F_HOST_TSO6) | BIT(LKL_VIRTIO_NET_F_GUEST_TSO6);
        // Host can merge receive buffers
        netdev_args.offload |= BIT(LKL_VIRTIO_NET_F_MRG_RXBUF);
    }

    int net_dev_id = lkl_netdev_add(netdev, &netdev_args);
    if (net_dev_id < 0) {
        fprintf(stderr, "Error: unable to register netdev, %s\n",
            lkl_strerror(net_dev_id));
        exit(net_dev_id);
    }

    return net_dev_id;
}

static void lkl_prepare_rootfs(const char* dirname, int perm) {
    int err = lkl_sys_access(dirname, /*LKL_S_IRWXO*/ F_OK);
    if (err < 0) {
        if (err == -LKL_ENOENT)
            err = lkl_sys_mkdir(dirname, perm);
        if (err < 0) {
            fprintf(stderr, "Error: Unable to mkdir %s: %s\n",
                dirname, lkl_strerror(err));
            exit(err);
        }
    }
}

static void lkl_copy_blkdev_nodes(const char* srcdir, const char* dstdir) {
    int err = 0;
    struct lkl_dir *dir = lkl_opendir(srcdir, &err);
    if (dir == NULL || err != 0) {
        fprintf(stderr, "Error: unable to opendir(%s)\n", srcdir);
        exit(err == 0 ? 1 : err);
    }

    char srcbuf[512] = {0};
    char dstbuf[512] = {0};
    strncpy(srcbuf, srcdir, sizeof(srcbuf));
    strncpy(dstbuf, dstdir, sizeof(dstbuf));
    int srcdir_len = strlen(srcbuf);
    int dstdir_len = strlen(dstbuf);
    if (srcbuf[srcdir_len-1] != '/')
        srcbuf[srcdir_len++] = '/';
    if (dstbuf[dstdir_len-1] != '/')
        dstbuf[dstdir_len++] = '/';
    struct lkl_linux_dirent64 *dev = NULL;
    int disknum = 0;
    while ((dev = lkl_readdir(dir)) != NULL) {
        strncpy(srcbuf+srcdir_len, dev->d_name, sizeof(srcbuf)-srcdir_len);
        strncpy(dstbuf+dstdir_len, dev->d_name, sizeof(dstbuf)-dstdir_len);
        struct lkl_stat stat;
        err = lkl_sys_stat(srcbuf, &stat);
        if (err != 0) {
            fprintf(stderr, "Error: lkl_sys_stat(%s) %s\n",
                srcbuf, lkl_strerror(err));
            exit(err);
        }
        if (!LKL_S_ISBLK(stat.st_mode))
            continue;

        lkl_sys_unlink(dstbuf);
        err = lkl_sys_mknod(dstbuf, LKL_S_IFBLK | 0600, stat.st_rdev);
        if (err != 0) {
            fprintf(stderr, "Error: lkl_sys_mknod(%s) %s\n",
                dstbuf, lkl_strerror(err));
            exit(err);
        }
    }
    err = lkl_errdir(dir);
    if (err != 0) {
        fprintf(stderr, "Error: lkl_readdir(%s) = %d\n", srcdir, err);
        exit(err);
    }

    err = lkl_closedir(dir);
    if (err != 0) {
        fprintf(stderr, "Error: lkl_closedir(%s) = %d\n", srcdir, err);
        exit(err);
    }
}

static void lkl_mount_devtmpfs(const char* mntpoint) {
    int err = lkl_sys_mount("devtmpfs", (char*) mntpoint, "devtmpfs", 0, NULL);
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mount(devtmpfs): %s\n",
            lkl_strerror(err));
        exit(err);
    }
}

static void lkl_mount_shmtmpfs() {
    int err = lkl_sys_mount("tmpfs", "/dev/shm", "tmpfs", 0, "rw,nodev");
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mount(tmpfs) (/dev/shm): %s\n",
            lkl_strerror(err));
        exit(err);
    }
}

static void lkl_mount_tmpfs() {
    int err = lkl_sys_mount("tmpfs", "/tmp", "tmpfs", 0, "mode=0777");
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mount(tmpfs): %s\n",
            lkl_strerror(err));
        exit(err);
    }
}

static void lkl_mount_mntfs() {
    int err = lkl_sys_mount("tmpfs", "/mnt", "tmpfs", 0, "mode=0777");
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mount(tmpfs): %s\n",
            lkl_strerror(err));
        exit(err);
    }
}

static void lkl_mount_sysfs() {
    int err = lkl_sys_mount("none", "/sys", "sysfs", 0, NULL);
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mount(sysfs): %s\n",
            lkl_strerror(err));
        exit(err);
    }
}

static void lkl_mount_runfs() {
    int err = lkl_sys_mount("tmpfs", "/run", "tmpfs", 0, "mode=0700");
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mount(tmpfs): %s\n",
            lkl_strerror(err));
        exit(err);
    }
}

static void lkl_mount_procfs() {
    int err = lkl_sys_mount("proc", "/proc", "proc", 0, NULL);
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mount(procfs): %s\n",
            lkl_strerror(err));
        exit(err);
    }
}

static void lkl_mknods() {
    lkl_sys_unlink("/dev/null");
    int err = lkl_sys_mknod("/dev/null", LKL_S_IFCHR | 0666, LKL_MKDEV(1,3));
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mknod(/dev/null) %s\n",
            lkl_strerror(err));
        exit(err);
    }
    lkl_sys_unlink("/dev/zero");
    err = lkl_sys_mknod("/dev/zero", LKL_S_IFCHR | 0666, LKL_MKDEV(1,5));
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mknod(/dev/zero) %s\n",
                lkl_strerror(err));
        exit(err);
    }
    lkl_sys_unlink("/dev/random");
    err = lkl_sys_mknod("/dev/random", LKL_S_IFCHR | 0444, LKL_MKDEV(1,8));
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mknod(/dev/random) %s\n",
                lkl_strerror(err));
        exit(err);
    }
    lkl_sys_unlink("/dev/urandom");
    err = lkl_sys_mknod("/dev/urandom", LKL_S_IFCHR | 0444, LKL_MKDEV(1,9));
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_mknod(/dev/urandom) %s\n",
                lkl_strerror(err));
        exit(err);
    }
}

static int lkl_mount_blockdev(const char* dev_str, const char* mnt_point,
                       const char *fs_type, int flags, const char* data) {
    char _data[4096];
    int err;

    err = lkl_sys_access("/mnt", LKL_S_IRWXO);
    if (err < 0) {
        if (err == -LKL_ENOENT)
            err = lkl_sys_mkdir("/mnt", 0700);
        if (err < 0)
            goto fail;
    }

    err = lkl_sys_mkdir(mnt_point, 0700);
    if (err < 0)
        goto fail;

    if (data) {
        strncpy(_data, data, sizeof(_data));
        _data[sizeof(_data) - 1] = 0;
    } else {
        _data[0] = 0;
    }

    err = lkl_sys_mount((char*)dev_str, (char*)mnt_point, (char*)fs_type, flags, _data);
    if (err < 0) {
        lkl_sys_rmdir(mnt_point);
        goto fail;
    }

fail:
    return err;
}

struct lkl_crypt_device {
    char *disk_path;
    int readonly;
    struct enclave_disk_config *disk_config;
};

static void* lkl_activate_crypto_disk_thread(struct lkl_crypt_device* lkl_cd) {
    int err;

    char* disk_path = lkl_cd->disk_path;

    struct crypt_device *cd;
    err = crypt_init(&cd, disk_path);
    if (err != 0) {
        fprintf(stderr, "Error: crypt_init(): %s (%d)\n", strerror(err), err);
        exit(err);
    }

    err = crypt_load(cd, CRYPT_LUKS, NULL);
    if (err != 0) {
        fprintf(stderr, "Error: crypt_load(): %s (%d)\n", strerror(err), err);
        exit(err);
    }

    // Copy decryption keys into enclave (debug-only).
    char *key_outside = lkl_cd->disk_config->key;
    lkl_cd->disk_config->key = (char *) lkl_sys_mmap(NULL, lkl_cd->disk_config->key_len, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if ((int64_t) lkl_cd->disk_config->key <= 0) {
        fprintf(stderr, "Error: Unable to allocate memory for disk encryption key inside the enclave: %s\n", lkl_strerror((int) lkl_cd->disk_config->key));
        exit(EXIT_FAILURE);
    }
    memcpy(lkl_cd->disk_config->key, key_outside, lkl_cd->disk_config->key_len);

    err = crypt_activate_by_passphrase(cd, "cryptroot", CRYPT_ANY_SLOT, lkl_cd->disk_config->key, lkl_cd->disk_config->key_len, lkl_cd->readonly ? CRYPT_ACTIVATE_READONLY : 0);
    if (err == -1) {
        fprintf(stderr, "Error: Unable to activate encrypted disk. Please ensure you have provided the correct passphrase/keyfile!\n");
        exit(err);
    } else if (err != 0) {
        fprintf(stderr, "Error: Unable to activate encrypted disk due to unknown error (error code: %d)\n", err);
        exit(err);
    }

    crypt_free(cd);

    // The key is only needed during activation, so don't keep it around
    // afterwards and free up space.
    memset(lkl_cd->disk_config->key, 0, lkl_cd->disk_config->key_len);

    unsigned long munmap_ret;
    if((munmap_ret = lkl_sys_munmap((unsigned long) lkl_cd->disk_config->key, lkl_cd->disk_config->key_len))) {
        fprintf(stderr, "Error: Unable to unmap memory for disk encryption key: %s\n", lkl_strerror((int) munmap_ret));
        exit(EXIT_FAILURE);
    }
    lkl_cd->disk_config->key = NULL;
    lkl_cd->disk_config->key_len = 0;

    return 0;
}

/* XXX(lukegb): don't abuse cryptsetup's internal, unexported hex-to-bytes function */
extern ssize_t crypt_hex_to_bytes(const char *hex, char **result, int safe_alloc);

static void* lkl_activate_verity_disk_thread(struct lkl_crypt_device* lkl_cd) {
    int err;

    char* disk_path = lkl_cd->disk_path;

    struct crypt_device *cd;
    // cryptsetup!
    err = crypt_init(&cd, disk_path);
    if (err != 0) {
        fprintf(stderr, "Error: crypt_init(): %s (%d)\n", strerror(err), err);
        exit(err);
    }

    /*
     * The dm-verity Merkle tree that contains the hashes of all data blocks is
     * stored on the disk image following the actual data blocks. The offset that
     * signifies both the end of the data region as well as the start of the hash
     * region has to be provided to SGX-LKL.
     */
    struct crypt_params_verity verity_params = {
        .data_device = disk_path,
        .hash_device = disk_path,
        .hash_area_offset = lkl_cd->disk_config->roothash_offset,
        .data_size = lkl_cd->disk_config->roothash_offset / 512, // In blocks, divide by block size
        .data_block_size = 512,
        .hash_block_size = 512,
    };

    err = crypt_load(cd, CRYPT_VERITY, &verity_params);
    if (err != 0) {
        fprintf(stderr, "Error: crypt_load(): %s (%d)\n", strerror(err), err);
        exit(err);
    }

    char* volume_hash_bytes = NULL;
    ssize_t hash_size = crypt_get_volume_key_size(cd);
    if (crypt_hex_to_bytes(lkl_cd->disk_config->roothash, &volume_hash_bytes, 0) != hash_size) {
        fprintf(stderr, "Invalid root hash string specified!\n");
        exit(1);
    }

    err = crypt_activate_by_volume_key(cd, "verityroot", volume_hash_bytes, 32, lkl_cd->readonly ? CRYPT_ACTIVATE_READONLY : 0);
    if (err != 0) {
        fprintf(stderr, "Error: crypt_activate_by_volume_key(): %s (%d)\n", strerror(err), err);
        exit(err);
    }

    crypt_free(cd);
    free(volume_hash_bytes);

    return NULL;
}

static void lkl_run_in_kernel_stack(void *(*start_routine) (void *), void* arg) {
    int err;

    /*
     * We need to pivot to a stack which is inside LKL's known memory mappings
     * otherwise get_user_pages will not manage to find the mapping, and will
     * fail.
     *
     * Buffers passed to the kernel via the crypto API need to be allocated
     * on this stack, or on heap pages allocated via lkl_sys_mmap.
     */
    const int stack_size = 32*1024;

    void* addr = lkl_sys_mmap(NULL, stack_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        fprintf(stderr, "Error: lkl_sys_mmap failed\n");
        exit(1);
    }

    pthread_t pt;
    pthread_attr_t ptattr;
    pthread_attr_init(&ptattr);
    pthread_attr_setstack(&ptattr, addr, stack_size);
    err = pthread_create(&pt, &ptattr, start_routine, arg);
    if (err < 0) {
        fprintf(stderr, "Error: pthread_create()=%s (%d)\n", strerror(err), err);
        exit(err);
    }

    err = pthread_join(pt, NULL);
    if (err < 0) {
        fprintf(stderr, "Error: pthread_join()=%s (%d)\n", strerror(err), err);
        exit(err);
    }
}

static void lkl_poststart_root_disk(struct enclave_disk_config *disk) {
    int err = 0;
    lkl_mount_devtmpfs("/dev");
    lkl_prepare_rootfs("/proc", 0700);
    lkl_mount_procfs();
    lkl_prepare_rootfs("/sys", 0700);
    lkl_mount_sysfs();
    lkl_prepare_rootfs("/run", 0700);
    lkl_mount_runfs();
    char mnt_point[] = {"/mnt/vda"};
    char dev_str_raw[] = {"/dev/vda"};

    char dev_str_enc[] = {"/dev/mapper/cryptroot"};
    char dev_str_verity[] = {"/dev/mapper/verityroot"};

    char *dev_str = dev_str_raw;
    char new_dev_str[] = {"/mnt/vda/dev/"};

    int lkl_trace_lkl_syscall_bak = sgxlkl_trace_lkl_syscall;
    int lkl_trace_internal_syscall_bak = sgxlkl_trace_internal_syscall;

    if ((sgxlkl_trace_lkl_syscall || sgxlkl_trace_internal_syscall) && (getenv("SGXLKL_HD_VERITY") != NULL || disk->enc)) {
        sgxlkl_trace_lkl_syscall = 0;
        sgxlkl_trace_internal_syscall = 0;
        SGXLKL_VERBOSE("Disk encryption/integrity requested: temporarily disabling lkl_strace\n");
    }

        struct lkl_crypt_device lkl_cd;
        lkl_cd.disk_path = dev_str;
        lkl_cd.readonly = disk->ro;
        lkl_cd.disk_config = disk;


        if (disk->roothash != NULL) {
            lkl_run_in_kernel_stack((void * (*)(void *)) &lkl_activate_verity_disk_thread, (void *) &lkl_cd);

            // We now want to mount the verified volume
            dev_str = dev_str_verity;
            lkl_cd.disk_path = dev_str_verity;
            // dm-verity is read only
            disk->ro = 1;
            lkl_cd.readonly = 1;
        }
        if (disk->enc) {
            lkl_run_in_kernel_stack((void * (*)(void *)) &lkl_activate_crypto_disk_thread, (void *) &lkl_cd);

            // We now want to mount the decrypted volume
            dev_str = dev_str_enc;
        }

    if ((lkl_trace_lkl_syscall_bak && !sgxlkl_trace_lkl_syscall) || (lkl_trace_internal_syscall_bak && !sgxlkl_trace_internal_syscall)) {
        SGXLKL_VERBOSE("Devicemapper setup complete: reenabling lkl_strace\n");
        sgxlkl_trace_lkl_syscall = lkl_trace_lkl_syscall_bak;
        sgxlkl_trace_internal_syscall = lkl_trace_internal_syscall_bak;
    }

    err = lkl_mount_blockdev(dev_str, mnt_point, "ext4", disk->ro ? LKL_MS_RDONLY : 0, NULL);
    if (err < 0) {
        fprintf(stderr, "Error: lkl_mount_blockdev()=%s (%d)\n",
            lkl_strerror(err), err);
        exit(err);
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
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_chroot(%s): %s\n",
            mnt_point, lkl_strerror(err));
        exit(err);
    }

    err = lkl_sys_chdir("/");
    if (err != 0) {
        fprintf(stderr, "Error: lkl_sys_chdir(%s): %s\n",
            mnt_point, lkl_strerror(err));
        exit(err);
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
    lkl_mknods();
}

static void lkl_poststart_disks(struct enclave_disk_config* disks, size_t num_disks) {
    lkl_poststart_root_disk(&disks[0]);

    char dev_path[] = { "/dev/vdXX" };
    size_t dev_path_len = strlen(dev_path);
    for (size_t i = 1; i < num_disks; ++i) {
        // We assign dev paths from /dev/vda to /dev/vdz, assuming we won't need
        // support for more than 26 disks.
        if ('a' + i > 'z') {
            fprintf(stderr, "Error: Too many disks (maximum is 26). Failed to mount disk %d at %s.\n", i, disks[i].mnt);
            // Adjust number to number of mounted disks.
            num_disks = 26;
            return;
        }
        snprintf(dev_path, dev_path_len, "/dev/vd%c", 'a' + i);
        int err = lkl_mount_blockdev(dev_path, disks[i].mnt, "ext4", disks[i].ro ? LKL_MS_RDONLY : 0, NULL);
        if (err < 0) {
            fprintf(stderr, "Error: lkl_mount_blockdev()=%s (%d)\n", lkl_strerror(err), err);
            exit(err);
        }
    }
}

static void lkl_poststart_net(enclave_config_t* encl, int net_dev_id) {
    int res = 0;
    if (net_dev_id >= 0) {
        int ifidx = lkl_netdev_get_ifindex(net_dev_id);
        res = lkl_if_set_ipv4(ifidx, encl->net_ip4.s_addr, encl->net_mask4);
        if (res < 0) {
            fprintf(stderr, "Error: lkl_if_set_ipv4(): %s\n",
                lkl_strerror(res));
            exit(res);
        }
        res = lkl_if_up(ifidx);
        if (res < 0) {
            fprintf(stderr, "Error: lkl_if_up(eth0): %s\n",
                lkl_strerror(res));
            exit(res);
        }
        if (encl->net_gw4.s_addr > 0) {
            res = lkl_set_ipv4_gateway(encl->net_gw4.s_addr);
            if (res < 0) {
                fprintf(stderr, "Error: lkl_set_ipv4_gateway(): %s\n",
                    lkl_strerror(res));
                exit(res);
            }
        }

        if (sgxlkl_mtu) {
            lkl_if_set_mtu(ifidx, sgxlkl_mtu);
        }

    }
    res = lkl_if_up(1);
    if (res < 0) {
        fprintf(stderr, "Error: lkl_if_up(1=lo): %s\n",
            lkl_strerror(res));
        exit(res);
    }
}

static void init_random() {
    struct rand_pool_info *pool_info = 0;
    FILE *f;
    int fd;

    SGXLKL_VERBOSE("Adding entropy to entropy pool.\n");

    char buf[8] = {0};
    f  = fopen("/proc/sys/kernel/random/poolsize", "r");
    if (!f)
        goto err;
    if (fgets(buf, 8, f) == NULL)
        goto err;
    // /proc/sys/kernel/random/poolsize for kernel 2.6+ contains pool size in
    // bits, divide by 8 for number of bytes.
    int poolsize = atoi(buf) / 8;

    // To be on the safe side, add entropy equivalent to the pool size.
    pool_info = (struct rand_pool_info *) malloc(sizeof(pool_info) + poolsize);
    if (!pool_info)
        goto err;

    pool_info->entropy_count = poolsize * 8;
    pool_info->buf_size = poolsize;

    uint64_t *entropy_buf = (uint64_t *) pool_info->buf;
    for (int i = 0; i < poolsize / 8; i++) {
        // TODO Use intrinsics
        // if (!_rdrand64_step(&entropy_buf[i]))
        //    goto err;
        register uint64_t rd;
        __asm__ volatile ( "rdrand %0;" : "=r" ( rd ) );
        entropy_buf[i] = rd;
    }

    fd = open("/dev/random", O_RDONLY);
    if (ioctl(fd, RNDADDENTROPY, pool_info) == -1)
        goto err;

    goto out;
err:
    fprintf(stderr, "[ SGX-LKL ] Warning: Failed to add entropy to entropy pool.\n");
out:
    if (f)
        fclose(f);
    if (fd)
        close(fd);
    if (pool_info)
        free(pool_info);
}

void __lkl_start_init(enclave_config_t* encl) {
    size_t i;

    // Provide LKL host ops and virtio block device ops
    lkl_host_ops = sgxlkl_host_ops;
    if (getenv_bool("SGXLKL_HD_MMAP", 0))
        lkl_dev_blk_ops = sgxlkl_dev_blk_mem_ops;
    else
        lkl_dev_blk_ops = sgxlkl_dev_blk_ops;

    if (getenv_bool("SGXLKL_TRACE_LKL_SYSCALL", 0))
        sgxlkl_trace_lkl_syscall = 1;

    if (getenv_bool("SGXLKL_TRACE_INTERNAL_SYSCALL", 0))
        sgxlkl_trace_internal_syscall = 1;

    if (getenv_bool("SGXLKL_TRACE_SYSCALL", 0)) {
        sgxlkl_trace_lkl_syscall = 1;
        sgxlkl_trace_internal_syscall = 1;
        }

    if (getenv_bool("SGXLKL_TRACE_MMAP", 0))
        sgxlkl_trace_mmap = 1;

    if (getenv_bool("SGXLKL_TRACE_THREAD", 0))
        sgxlkl_trace_thread = 1;

    if (getenv_bool("SGXLKL_HOSTNET", 0))
        sgxlkl_use_host_network = 1;

    if (getenv_bool("SGXLKL_TAP_OFFLOAD", 0))
        sgxlkl_use_tap_offloading = 1;

    sgxlkl_mtu = (int) getenv_uint64("SGXLKL_TAP_MTU", 0, INT_MAX);

    if (getenv_bool("SGXLKL_MMAP_FILE_SUPPORT", 0))
        sgxlkl_mmap_file_support = 1;

    num_disks = encl->num_disks;
    if (num_disks <= 0) {
        fprintf(stderr, "Error: No root disk provided. Aborting...\n");
        exit(EXIT_FAILURE);
    }

    // We copy the disk config as we need to keep track of mount paths and can't
    // rely on the enclave_config to be around and unchanged for the lifetime of
    // the enclave.
    disks = (struct enclave_disk_config*) malloc(sizeof(struct enclave_disk_config) * num_disks);
    memcpy(disks, encl->disks, sizeof(struct enclave_disk_config) * num_disks);
    // Decryption keys are copied in lkl_activate_crypto_thread.

    lkl_prestart_disks(disks, num_disks);

    // Register network tap if given one
    int net_dev_id = -1;
    if (encl->net_fd != 0)
        net_dev_id = lkl_prestart_net(encl);

    // Start kernel threads (synchronous, doesn't return before kernel is ready)
    const char *lkl_cmdline = getenv("SGXLKL_CMDLINE");
    if (lkl_cmdline == NULL)
        lkl_cmdline = DEFAULT_LKL_CMDLINE;
    SGXLKL_VERBOSE("With command line: %s\n", lkl_cmdline);
    SGXLKL_VERBOSE("Using host networking stack: %s\n", (sgxlkl_use_host_network ? "YES" : "no"));
    SGXLKL_VERBOSE("Using LKL mmap file support: %s\n", (sgxlkl_mmap_file_support ? "YES" : "no"));
    for (i = 0; i < num_disks; ++i) {
        SGXLKL_VERBOSE("Disk %zu: Disk encryption: %s\n", i, (disks[i].enc ? "ON" : "off"));
        SGXLKL_VERBOSE("Disk %zu: Rootfs is writable: %s\n", i, (!disks[i].ro ? "YES" : "no"));
    }

    long res = lkl_start_kernel(&lkl_host_ops, lkl_cmdline);
    if (res < 0) {
        fprintf(stderr, "Error: could not start LKL kernel, %s\n",
            lkl_strerror(res));
        exit(res);
    }

    // Open dummy files to use LKL's 0/1/2 file descriptors
    // (otherwise they will be assigned to the app's first fopen()s
    // and become undistinguishable from STDIN/OUT/ERR)
    for (int i = 0; i < 3; i++) {
        int err = 0;
        lkl_opendir("/", &err);
        if (err != 0) {
            fprintf(stderr, "Error: unable to pad file descriptor table\n");
            exit(err);
        }
    }

    // Now that our kernel is ready to handle syscalls, mount root
    lkl_poststart_disks(disks, num_disks);

    init_random();

    // Set environment variable to export SHMEM address to the application.
    // Note: Due to how putenv() works, we need to allocate the environment
    // variable on the heap and we must _not_ free it (man putenv, section NOTES)
    char *shm_common = malloc(64);
    char *shm_enc_to_out_addr = malloc(64);
    char *shm_out_to_enc_addr = malloc(64);

    // Set address of ring buffer to env, so that enclave process can access it directly
    snprintf(shm_common, 64, "SGXLKL_SHMEM_COMMON=%p", encl->shm_common);
    snprintf(shm_enc_to_out_addr, 64, "SGXLKL_SHMEM_ENC_TO_OUT=%p", encl->shm_enc_to_out);
    snprintf(shm_out_to_enc_addr, 64, "SGXLKL_SHMEM_OUT_TO_ENC=%p", encl->shm_out_to_enc);
    putenv(shm_common);
    putenv(shm_enc_to_out_addr);
    putenv(shm_out_to_enc_addr);

    // Set interface status/IP/routes
    if (!sgxlkl_use_host_network)
        lkl_poststart_net(encl, net_dev_id);

    // Set hostname (provided through SGXLKL_HOSTNAME)
    sethostname(encl->hostname, strlen(encl->hostname));
}

/* Requires starttime to be higher or equal to endtime */
int timespec_diff(struct timespec *starttime, struct timespec *endtime, struct timespec *diff) {
    if (starttime->tv_sec > endtime->tv_sec || (starttime->tv_sec == endtime->tv_sec && starttime->tv_nsec > endtime->tv_nsec)) {
        errno = EINVAL;
        return -1;
    }

    diff->tv_sec = endtime->tv_sec - starttime->tv_sec;
    if (starttime->tv_nsec > endtime->tv_nsec) {
        diff->tv_sec--;
    }

    diff->tv_nsec = (1000000000 + endtime->tv_nsec - starttime->tv_nsec) % 1000000000;

    return 0;
}

void __lkl_exit() {
    if (getenv("SGXLKL_PRINT_APP_RUNTIME")) {
        struct timespec endtime, runtime;
        clock_gettime(CLOCK_MONOTONIC, &endtime);
        timespec_diff(&sgxlkl_app_starttime, &endtime, &runtime);
        printf("Application runtime: %lld.%.9lds\n", runtime.tv_sec, runtime.tv_nsec);
    }

    long res;
    for (int i = num_disks - 1; i >= 0; --i) {
        res = lkl_umount_timeout(disks[i].mnt, 0, UMOUNT_DISK_TIMEOUT);
        if (res < 0) {
            fprintf(stderr, "Error: Could not unmount disk %d, %s\n", i, lkl_strerror(res));
        }

        // Root disk, no need to remove mount point ("/").
        if (i == 0) break;


        // Not really necessary for mounts in /mnt since /mnt is
        // mounted as tmpfs itself, but it is also possible to mount
        // secondary images at any place in the root file system,
        // including persistent storage, if the root file system is
        // writeable. For simplicity, remove all mount points here.
        //
        // Note: We currently do not support pre-existing mount points
        // on read-only file systems.
        res = lkl_sys_rmdir(disks[i].mnt);
        if (res < 0) {
            fprintf(stderr, "Error: Could not remove mount point %s\n", disks[i].mnt, lkl_strerror(res));
        }
    }

    res = lkl_sys_halt();
    if (res < 0) {
        fprintf(stderr, "Error: LKL halt, %s\n",
            lkl_strerror(res));
        exit(res);
    }
}
