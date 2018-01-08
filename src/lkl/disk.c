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
#include "lkl/disk.h"
#include "lkl/aes.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "syscall.h"

#define DEFAULT_ENCRYPTION_BUF_LEN (512*80)

static int disk_encrypted = 0;
// Default hardcoded encryption key. In an SGX-ready production environment,
// this would be unsealed by the CPU.
static unsigned char disk_encryption_key[32] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
	0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,
	0x1E,0x1F
};

static int fd_get_capacity(struct lkl_disk disk, unsigned long long *res)
{
	off_t off;

	off = host_syscall_SYS_lseek(disk.fd, 0, SEEK_END);
	if (off < 0)
		return -1;

	*res = off;
	return 0;
}

// Reads and write requests sent to the following functions are always sector-
// aligned (on 512 bytes). Unaligned requests are fixed by the virtio backend.

static int do_plain_rw(ssize_t (*fn)(), struct lkl_disk disk, struct lkl_blk_req *req)
{
	off_t off = req->sector * 512;
	char *addr;
	int len;
	int i;
	int ret = 0;
	for (i = 0; i < req->count; i++) {
		addr = req->buf[i].iov_base;
		len = req->buf[i].iov_len;
		do {
			ret = fn(disk.fd, addr, len, off);
			if (ret <= 0)
				return ret;
			addr += ret;
			len -= ret;
			off += ret;
		} while (len > 0);
	}
	return ret;
}

#ifndef NO_OPENSSL
static int do_read_decrypt(struct lkl_disk disk, struct lkl_blk_req *req)
{
	static unsigned char *dec_buf = NULL;
	static size_t dec_buf_len = DEFAULT_ENCRYPTION_BUF_LEN;
	if (dec_buf == NULL) {
		dec_buf = malloc(dec_buf_len);
		if (dec_buf == NULL) {
			fprintf(stderr, "Error: blkdev decryption, OOM\n");
			return -1;
		}
	}

	off_t off = req->sector * 512;
	int ret = 0;
	for (int i = 0; i < req->count; i++) {
		unsigned char* end_addr = req->buf[i].iov_base;
		int end_len = req->buf[i].iov_len;
		while (end_len > dec_buf_len) {
			dec_buf_len *= 2;
			dec_buf = realloc(dec_buf, dec_buf_len);
			if (dec_buf == NULL) {
				fprintf(stderr, "Error: blkdev decryption, OOM\n");
				return -1;
			}
		}
		unsigned char* addr = dec_buf;
		int len = end_len;
		do {
			ret = host_syscall_SYS_pread64(disk.fd, addr, len, off);
			if (ret <= 0)
				return ret;
			addr += ret;
			len -= ret;
			off += ret;
		} while (len > 0);

		for (int j = 0; j < (end_len/512); j++) {
			int deciphered_bytes = 512;
			int res = blockdev_decrypt(dec_buf + 512 * j, 512,
				end_addr + 512 * j, &deciphered_bytes,
				req->sector + j, disk_encryption_key);
			if (res != 0 || deciphered_bytes != 512) {
				fprintf(stderr, "Error: blkdev decryption, "
					"code %d at sector %d\n", res,
					req->sector + j);
				return (res > 0 ? -res : res);
			}
		}
	}
	return ret;
}

static int do_encrypt_write(struct lkl_disk disk, struct lkl_blk_req *req)
{
	static unsigned char *enc_buf = NULL;
	static size_t enc_buf_len = DEFAULT_ENCRYPTION_BUF_LEN;
	if (enc_buf == NULL) {
		enc_buf = malloc(enc_buf_len);
		if (enc_buf == NULL) {
			fprintf(stderr, "Error: blkdev encryption, OOM\n");
			return -1;
		}
	}

	off_t off = req->sector * 512;
	int ret = 0;
	for (int i = 0; i < req->count; i++) {
		unsigned char* addr = req->buf[i].iov_base;
		int len = req->buf[i].iov_len;
		while (len > enc_buf_len) {
			enc_buf_len *= 2;
			enc_buf = realloc(enc_buf, enc_buf_len);
			if (enc_buf == NULL) {
				fprintf(stderr, "Error: blkdev encryption, OOM\n");
				return -1;
			}
		}
		for (int j = 0; j < (len/512); j++) {
			int encrypted_bytes = 512;
			int res = blockdev_encrypt(addr + 512 * j, 512,
				enc_buf + 512 * j, &encrypted_bytes,
				req->sector + j, disk_encryption_key);
			if (res != 0 || encrypted_bytes != 512) {
				fprintf(stderr, "Error: blkdev encryption, "
					"code %d at sector %d\n", res,
					req->sector + j);
				return (res > 0 ? -res : res);
			}
		}
		addr = enc_buf;
		do {
			ret = host_syscall_SYS_pwrite64(disk.fd, addr, len, off);
			if (ret <= 0)
				return ret;
			addr += ret;
			len -= ret;
			off += ret;
		} while (len > 0);
	}
	return ret;
}
#endif

static int blk_plaintext_request(struct lkl_disk disk, struct lkl_blk_req *req)
{
	int err = 0;
	switch (req->type) {
	case LKL_DEV_BLK_TYPE_READ:
		err = do_plain_rw(&host_syscall_SYS_pread64, disk, req);
		// Uncomment the following and comment the previous line if
		// you need scatter-gather I/O functions.
		/*err = host_syscall_SYS_preadv(disk.fd, (struct iovec*)(req->buf), req->count,
			(long)(req->sector*512), // offset low 32 bits
			(long)((req->sector*512)>>32) // offset high 32 bits
		);*/
		break;
	case LKL_DEV_BLK_TYPE_WRITE:
		err = do_plain_rw(&host_syscall_SYS_pwrite64, disk, req);
		/*err = host_syscall_SYS_pwritev(disk.fd, (struct iovec*)(req->buf), req->count,
			(long)(req->sector*512),
			(long)((req->sector*512)>>32)
		);*/
		break;
	case LKL_DEV_BLK_TYPE_FLUSH:
	case LKL_DEV_BLK_TYPE_FLUSH_OUT:
		err = host_syscall_SYS_fdatasync(disk.fd);
		break;
	default:
		return LKL_DEV_BLK_STATUS_UNSUP;
	}

	if (err < 0)
		return LKL_DEV_BLK_STATUS_IOERR;
	return LKL_DEV_BLK_STATUS_OK;
}

#ifndef NO_OPENSSL
static int blk_cipher_request(struct lkl_disk disk, struct lkl_blk_req *req)
{
	int err = 0;
	switch (req->type) {
	case LKL_DEV_BLK_TYPE_READ:
		err = do_read_decrypt(disk, req);
		break;
	case LKL_DEV_BLK_TYPE_WRITE:
		err = do_encrypt_write(disk, req);
		break;
	case LKL_DEV_BLK_TYPE_FLUSH:
	case LKL_DEV_BLK_TYPE_FLUSH_OUT:
		err = host_syscall_SYS_fdatasync(disk.fd);
		break;
	default:
		return LKL_DEV_BLK_STATUS_UNSUP;
	}

	if (err < 0)
		return LKL_DEV_BLK_STATUS_OK;
}
#endif

struct lkl_dev_blk_ops sgxlkl_dev_plaintext_blk_ops = {
	.get_capacity = fd_get_capacity,
	.request = blk_plaintext_request,
};

#ifndef NO_OPENSSL
struct lkl_dev_blk_ops sgxlkl_dev_cipher_blk_ops = {
	.get_capacity = fd_get_capacity,
	.request = blk_cipher_request,
};
#endif
