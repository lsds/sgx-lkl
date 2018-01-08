/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * 
 * This file is part of SGX-LKL.
 * 
 * SGX-LKL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SGX-LKL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SGX-LKL.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <lkl_host.h>
#include "lkl/disk.h"
#include "lkl/posix-host.h"
#include "lkl/setup.h"
#include "lkl/virtio_net.h"
#include "sgxlkl_debug.h"

#ifndef NO_CRYPTSETUP
#include "libcryptsetup.h"
#include "libdevmapper.h"
#endif

int sethostname(const char *, size_t);

int sgxlkl_trace_syscall = 0;
int sgxlkl_trace_mmap = 0;
int sgxlkl_trace_thread = 0;
int sgxlkl_use_host_network = 0;
int sgxlkl_mmap_file_support = 0;

#ifndef NO_CRYPTSETUP
static const char* lkl_encryption_key = "FOO";
#endif

int get_env_bool(const char *name, int def)
{
	char *env = getenv(name);
	if (env == NULL)
		return def;
	if (def)
		return (strncmp(env, "0", 1) != 0);
	else
		return (strncmp(env, "1", 1) == 0);
}

static unsigned long long get_env_bytes(const char *name, unsigned long long def)
{
	char *env = getenv(name);
	if (env == NULL)
		return def;
	char *suffix = NULL;
	unsigned long long res = strtoul(env, &suffix, 10);
	if (res == 0) {
		fprintf(stderr, "Error: unable to parse RAM argument\n");
		exit(1);
	}
	if (suffix == NULL || *suffix == '\0')
		return res;
	switch (tolower(*suffix)) {
	case 'k':
		res *= 1024;
		break;
	case 'm':
		res *= 1024*1024;
		break;
	case 'g':
		res *= 1024*1024*1024;
		break;
	default:
		fprintf(stderr, "Error: unable to parse RAM unit\n");
		exit(2);
	}
	return res;
}

static int lkl_prestart_disks(enclave_config_t* encl)
{
	int fd = encl->disk_fd;
	struct lkl_disk disk;
        /* Set ops to NULL to use platform default ops */
	disk.ops = NULL;
	disk.fd = encl->disk_fd;
	int disk_dev_id = lkl_disk_add(&disk);
	if (disk_dev_id < 0) {
		fprintf(stderr, "Error: unable to register disk, %s\n",
			lkl_strerror(disk_dev_id));
		exit(disk_dev_id);
	}
	return disk_dev_id;
}

static int lkl_prestart_net(enclave_config_t* encl)
{
	int fd = encl->net_fd;
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
	int net_dev_id = lkl_netdev_add(netdev, &netdev_args);
	if (net_dev_id < 0) {
		fprintf(stderr, "Error: unable to register netdev, %s\n",
			lkl_strerror(net_dev_id));
		exit(net_dev_id);
	}
	return net_dev_id;
}

static void lkl_prepare_rootfs(const char* dirname, int perm)
{
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

static void lkl_copy_blkdev_nodes(const char* srcdir, const char* dstdir)
{
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

static void lkl_mount_devtmpfs(const char* mntpoint)
{
	int err = lkl_sys_mount("devtmpfs", (char*) mntpoint, "devtmpfs", 0, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: lkl_sys_mount(devtmpfs): %s\n",
			lkl_strerror(err));
		exit(err);
	}
}

static void lkl_mount_tmpfs()
{
	int err = lkl_sys_mount("tmpfs", "/tmp", "tmpfs", 0, "mode=0777");
	if (err != 0) {
		fprintf(stderr, "Error: lkl_sys_mount(tmpfs): %s\n",
			lkl_strerror(err));
		exit(err);
	}
}

static void lkl_mount_sysfs()
{
	int err = lkl_sys_mount("none", "/sys", "sysfs", 0, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: lkl_sys_mount(sysfs): %s\n",
			lkl_strerror(err));
		exit(err);
	}
}

static void lkl_mount_procfs()
{
	int err = lkl_sys_mount("proc", "/proc", "proc", 0, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: lkl_sys_mount(procfs): %s\n",
			lkl_strerror(err));
		exit(err);
	}
}

static void lkl_mknods()
{
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

static int lkl_create_blockdev(unsigned int disk_id, const char* devname)
{
	unsigned int dev;
	int err;


	err = lkl_get_virtio_blkdev(disk_id, 0, &dev);
	if (err < 0)
		goto fail;

	err = lkl_sys_access("/dev", LKL_S_IRWXO);
	if (err < 0) {
		if (err == -LKL_ENOENT)
			err = lkl_sys_mkdir("/dev", 0700);
		if (err < 0)
			goto fail;
	}

	err = lkl_sys_mknod(devname, LKL_S_IFBLK | 0600, dev);
	if (err < 0)
		return err;

fail:
	return err;
}

static int lkl_mount_blockdev(const char* dev_str, const char* mnt_point,
		               const char *fs_type, int flags, const char* data)
{
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

#ifndef NO_CRYPTSETUP
static void* lkl_activate_crypto_disk_thread(void* disk_path_vd)
{
	int err;

	char* disk_path = (char*)disk_path_vd;

	struct crypt_device *cd;
	// cryptsetup!
	err = crypt_init(&cd, disk_path);
	if (err != 0) {
		fprintf(stderr, "Error: crypt_init(): %s (%d)\n", strerror(err), err);
		exit(err);
	}

	err = crypt_load(cd, CRYPT_LUKS1, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: crypt_load(): %s (%d)\n", strerror(err), err);
		exit(err);
	}

	err = crypt_activate_by_passphrase(cd, "cryptroot", CRYPT_ANY_SLOT, lkl_encryption_key, strlen(lkl_encryption_key), CRYPT_ACTIVATE_READONLY);
	if (err != 0) {
		fprintf(stderr, "Error: crypt_activate_by_passphrase(): %s (%d)\n", strerror(err), err);
		exit(err);
	}

	crypt_free(cd);

	return NULL;
}

/* XXX(lukegb): don't abuse cryptsetup's internal, unexported hex-to-bytes function */
extern ssize_t crypt_hex_to_bytes(const char *hex, char **result, int safe_alloc);

static void* lkl_activate_verity_disk_thread(void* disk_path_vd)
{
	int err;

	char* disk_path = (char*)disk_path_vd;

	struct crypt_device *cd;
	// cryptsetup!
	err = crypt_init(&cd, disk_path);
	if (err != 0) {
		fprintf(stderr, "Error: crypt_init(): %s (%d)\n", strerror(err), err);
		exit(err);
	}

	/* XXX(lukegb): calculate disk correctly
	 * this is calculated as IMAGE_SIZE_MB + LUKS_HEADER_BLOCKS */
	const int disk_size = 100 + 5; /* MB */

	struct crypt_params_verity verity_params = {
		.data_device = disk_path,
		.hash_device = disk_path,
		.hash_area_offset = disk_size*1024*1024,
		.data_size = disk_size*2048,
		.data_block_size = 512,
		.hash_block_size = 512,
	};

	err = crypt_load(cd, CRYPT_VERITY, &verity_params);
	if (err != 0) {
		fprintf(stderr, "Error: crypt_load(): %s (%d)\n", strerror(err), err);
		exit(err);
	}

	const char* volume_hash = getenv("SGXLKL_HD_VERITY");
	char* volume_hash_bytes = NULL;

	ssize_t hash_size = crypt_get_volume_key_size(cd);
	if (crypt_hex_to_bytes(volume_hash, &volume_hash_bytes, 0) != hash_size) {
		fprintf(stderr, "Invalid root hash string specified!\n");
		exit(1);
	}

	err = crypt_activate_by_volume_key(cd, "verityroot", volume_hash_bytes, 32, CRYPT_ACTIVATE_READONLY);
	if (err != 0) {
		fprintf(stderr, "Error: crypt_activate_by_volume_key(): %s (%d)\n", strerror(err), err);
		exit(err);
	}

	crypt_free(cd);
	free(volume_hash_bytes);

	return NULL;
}

static void lkl_run_in_kernel_stack(void *(*start_routine) (void *), void* arg)
{
	int err;

	/*
	 * we need to pivot to a stack which is inside LKL's known memory mappings
	 * otherwise get_user_pages will not manage to find the mapping, and will
	 * fail.
	 *
	 * 4kB stack is too small. 8kB works for the moment, so I'll leave it at that. -lukegb
	 */
	const int stack_size = 8192;

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
#endif

static void lkl_poststart_disks(enclave_config_t* encl, int disk_dev_id)
{
	int err = 0;
	lkl_mount_devtmpfs("/dev");
	lkl_prepare_rootfs("/proc", 0700);
	lkl_mount_procfs();
	lkl_prepare_rootfs("/sys", 0700);
	lkl_mount_sysfs();
	if (disk_dev_id >= 0) {
		char mnt_point[] = {"/mnt/vda"};
		char dev_str_raw[] = {"/dev/vda"};
#ifndef NO_CRYPTSETUP
		char dev_str_enc[] = {"/dev/mapper/cryptroot"};
		char dev_str_verity[] = {"/dev/mapper/verityroot"};
#endif
		char *dev_str = dev_str_raw;
		char new_dev_str[] = {"/mnt/vda/dev/"};

#ifndef NO_CRYPTSETUP
		int lkl_trace_syscall_bak = sgxlkl_trace_syscall;

		if (lkl_strace && (getenv("SGXLKL_HD_VERITY") != NULL || encl->disk_enc)) {
			sgxlkl_trace_syscall = 0;
			SGXLKL_VERBOSE("Disk encryption/integrity requested: temporarily disabling lkl_strace\n");
		}

		if (getenv("SGXLKL_HD_VERITY") != NULL) {
			lkl_run_in_kernel_stack(&lkl_activate_verity_disk_thread, dev_str);

			/* we now want to mount the verified volume */
			dev_str = dev_str_verity;
		}
		if (encl->disk_enc) {
			lkl_run_in_kernel_stack(&lkl_activate_crypto_disk_thread, dev_str);

			/* we now want to mount the decrypted volume */
			dev_str = dev_str_enc;
		}

		if (lkl_trace_syscall_bak && !sgxlkl_trace_syscall) {
			SGXLKL_VERBOSE("Devicemapper setup complete: reenabling lkl_strace\n");
			sgxlkl_trace_syscall = lkl_trace_syscall_bak;
		}
#endif

		err = lkl_mount_blockdev(dev_str, mnt_point, "ext4", encl->disk_ro ? LKL_MS_RDONLY : 0, NULL);
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
	}
	lkl_prepare_rootfs("/dev", 0700);
	lkl_prepare_rootfs("/mnt", 0700);
	lkl_prepare_rootfs("/tmp", 0777);
	lkl_prepare_rootfs("/sys", 0700);
	lkl_prepare_rootfs("/proc", 0700);
	lkl_mount_tmpfs();
	lkl_mount_sysfs();
	lkl_mount_procfs();
	lkl_mknods();
}

static void lkl_poststart_net(enclave_config_t* encl, int net_dev_id)
{
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
	}
	res = lkl_if_up(1);
	if (res < 0) {
		fprintf(stderr, "Error: lkl_if_up(1=lo): %s\n",
			lkl_strerror(res));
		exit(res);
	}
}

void __lkl_start_init(enclave_config_t* encl)
{
	// Overwrite function pointers from LKL's posix-host.c with ours
	lkl_host_ops = sgxlkl_host_ops;
	lkl_dev_blk_ops = sgxlkl_dev_plaintext_blk_ops;
#ifndef NO_OPENSSL
	if (encl->disk_enc)
		lkl_dev_blk_ops = sgxlkl_dev_cipher_blk_ops;
#endif

	// LKL setup and boot can be disabled by env during tests
	// (in which case no LKL syscall must be thrown by Musl!)
	int lkl_needed = !get_env_bool("SGXLKL_NOLKL", 0);
	if (!lkl_needed)
		return;

	if (get_env_bool("SGXLKL_TRACE_SYSCALL", 0))
		sgxlkl_trace_syscall = 1;

	if (get_env_bool("SGXLKL_TRACE_MMAP", 0))
		sgxlkl_trace_mmap = 1;

	if (get_env_bool("SGXLKL_TRACE_THREAD", 0))
		sgxlkl_trace_thread = 1;

	if (get_env_bool("SGXLKL_HOSTNET", 0))
		sgxlkl_use_host_network = 1;

	if (get_env_bool("SGXLKL_MMAP_FILE_SUPPORT", 0))
		sgxlkl_mmap_file_support = 1;

	encl->disk_ro = get_env_bool("SGXLKL_HD_RW", 0) == 0;

	// Register hard drive if given one
	int disk_dev_id = -1;
	if (encl->disk_fd != 0)
		disk_dev_id = lkl_prestart_disks(encl);

	// Register network tap if given one
	int net_dev_id = -1;
	if (encl->net_fd != 0)
		net_dev_id = lkl_prestart_net(encl);

	// Start kernel threads (synchronous, doesn't return before kernel is ready)
	const char *lkl_cmdline = getenv("SGXLKL_CMDLINE");
	if (lkl_cmdline == NULL)
		lkl_cmdline = DEFAULT_LKL_CMDLINE;
	SGXLKL_VERBOSE("With command line: %s\n", lkl_cmdline);
	SGXLKL_VERBOSE("Disk encryption: %s\n", (encl->disk_enc ? "ON" : "off"));
	SGXLKL_VERBOSE("Using host networking stack: %s\n", (sgxlkl_use_host_network ? "YES" : "no"));
	SGXLKL_VERBOSE("Using LKL mmap file support: %s\n", (sgxlkl_mmap_file_support ? "YES" : "no"));
	SGXLKL_VERBOSE("Rootfs is writable: %s\n", (!encl->disk_ro ? "YES" : "no"));

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

	// Now that our kernel is ready to handle syscalls, mount a nice root
	lkl_poststart_disks(encl, disk_dev_id);

	// Set environment variable to export SHMEM address to the application.
	// Note: Due to how putenv() works, we need to allocate the environment
	// variable on the heap and we must _not_ free it (man putenv, section NOTES)
	char *shm_enc_to_out_addr = malloc(64);
	char *shm_out_to_enc_addr = malloc(64);

	// Set address of ring buffer to env, so that enclave process can access it directly
	snprintf(shm_enc_to_out_addr, 64, "SGXLKL_SHMEM_ENC_TO_OUT=%p", encl->shm_enc_to_out_q);
	snprintf(shm_out_to_enc_addr, 64, "SGXLKL_SHMEM_OUT_TO_ENC=%p", encl->shm_out_to_enc_q);
	putenv(shm_enc_to_out_addr);
	putenv(shm_out_to_enc_addr);

	// Set interface status/IP/routes
	if (!sgxlkl_use_host_network)
		lkl_poststart_net(encl, net_dev_id);

	// Set hostname (provided through SGXLKL_HOSTNAME)
	sethostname(encl->hostname, strlen(encl->hostname));

    SGXLKL_VERBOSE("Completed __lkl_start_init\n");
}

void __lkl_exit()
{
	int lkl_booted = !get_env_bool("SGXLKL_NOLKL", 0);
	int lkl_halt = !get_env_bool("SGXLKL_NOLKLHALT", 0);
	if (lkl_booted && lkl_halt) {
		long res = lkl_sys_halt();
		if (res < 0) {
			fprintf(stderr, "Error: LKL halt, %s\n",
				lkl_strerror(res));
			exit(res);
		}
	}
}
