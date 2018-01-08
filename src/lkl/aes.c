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

#ifndef NO_OPENSSL

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <openssl/evp.h>
#include "lkl/aes.h"

#define EVP_OR_GOTO_OUT(x) res = x; if (res != 1) { perror( #x ); goto out; }

typedef union aes_iv_plain64 {
	struct {
		uint64_t index;
		uint8_t zero_pad[AES_KEY_LENGTH-8];
	} sector;
	unsigned char aes_iv[AES_KEY_LENGTH];
} aes_iv_plain64;

typedef int (*blockdev_fn)(unsigned char*, int, unsigned char*, int*,
                           uint64_t, unsigned char*);

int blockdev_encrypt(unsigned char *plain_buf, int plain_len,
	unsigned char *cipher_buf, int *_cipher_len, uint64_t sector,
	unsigned char key[])
{
	aes_iv_plain64 iv;
	EVP_CIPHER_CTX ctx;
	int res = 1;
	int cipher_len = *_cipher_len;

	memset(&iv, 0, sizeof(iv));
	iv.sector.index = htole64(sector);

	EVP_OR_GOTO_OUT(EVP_EncryptInit(&ctx, EVP_aes_128_xts(), key, iv.aes_iv))
	EVP_OR_GOTO_OUT(EVP_EncryptUpdate(&ctx, cipher_buf, &cipher_len, plain_buf, plain_len))
	int cipher_len_added = 0;
	EVP_OR_GOTO_OUT(EVP_EncryptFinal(&ctx, cipher_buf + cipher_len, &cipher_len_added))
	cipher_len += cipher_len_added;

out:
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (res == 1)
		*_cipher_len = cipher_len;
	return (res != 1);
}

int blockdev_decrypt(unsigned char *cipher_buf, int cipher_len,
	unsigned char *plain_buf, int *_plain_len, uint64_t sector,
	unsigned char key[])
{
	aes_iv_plain64 iv;
	EVP_CIPHER_CTX ctx;
	int res = 1;
	int plain_len = 0;

	memset(&iv, 0, sizeof(iv));
	iv.sector.index = htole64(sector);

	EVP_OR_GOTO_OUT(EVP_DecryptInit(&ctx, EVP_aes_128_xts(), key, iv.aes_iv))
	EVP_OR_GOTO_OUT(EVP_DecryptUpdate(&ctx, plain_buf, &plain_len, cipher_buf, cipher_len))
	int plain_len_added = 0;
	EVP_OR_GOTO_OUT(EVP_DecryptFinal(&ctx, plain_buf + plain_len, &plain_len_added))
	plain_len += plain_len_added;

out:
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (res == 1)
		*_plain_len = plain_len;
	return (res != 1);
}

#endif
