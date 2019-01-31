/*
 * utils_crypt - cipher utilities for cryptsetup
 *
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2018, Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "libcryptsetup.h"
#include "utils_crypt.h"
#include "lkl_host.h"

int crypt_parse_name_and_mode(const char *s, char *cipher, int *key_nums,
			      char *cipher_mode)
{
	if (!s || !cipher || !cipher_mode)
		return -EINVAL;

	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]-%" MAX_CIPHER_LEN_STR "s",
		   cipher, cipher_mode) == 2) {
		if (!strcmp(cipher_mode, "plain"))
			strcpy(cipher_mode, "cbc-plain");
		if (key_nums) {
			char *tmp = strchr(cipher, ':');
			*key_nums = tmp ? atoi(++tmp) : 1;
			if (!*key_nums)
				return -EINVAL;
		}

		return 0;
	}

	/* Short version for "empty" cipher */
	if (!strcmp(s, "null") || !strcmp(s, "cipher_null")) {
		strcpy(cipher, "cipher_null");
		strcpy(cipher_mode, "ecb");
		if (key_nums)
			*key_nums = 0;
		return 0;
	}

	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]", cipher) == 1) {
		strcpy(cipher_mode, "cbc-plain");
		if (key_nums)
			*key_nums = 1;
		return 0;
	}

	return -EINVAL;
}

int crypt_parse_hash_integrity_mode(const char *s, char *integrity)
{
	char mode[MAX_CIPHER_LEN], hash[MAX_CIPHER_LEN];
	int r;

	if (!s || !integrity || strchr(s, '(') || strchr(s, ')'))
		return -EINVAL;

	r = sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]-%" MAX_CIPHER_LEN_STR "s", mode, hash);
	if (r == 2)
		r = snprintf(integrity, MAX_CIPHER_LEN, "%s(%s)", mode, hash);
	else if (r == 1)
		r = snprintf(integrity, MAX_CIPHER_LEN, "%s", mode);
	else
		return -EINVAL;

	if (r < 0 || r == MAX_CIPHER_LEN)
		return -EINVAL;

	return 0;
}

int crypt_parse_integrity_mode(const char *s, char *integrity,
			       int *integrity_key_size)
{
	int ks = 0, r = 0;

	if (!s || !integrity)
		return -EINVAL;

	// FIXME: do not hardcode it here

	/* AEAD modes */
	if (!strcmp(s, "aead") ||
	    !strcmp(s, "poly1305") ||
	    !strcmp(s, "none")) {
		strncpy(integrity, s, MAX_CIPHER_LEN);
		ks = 0;
	} else if (!strcmp(s, "hmac-sha256")) {
		strncpy(integrity, "hmac(sha256)", MAX_CIPHER_LEN);
		ks = 32;
	} else if (!strcmp(s, "hmac-sha512")) {
		ks = 64;
		strncpy(integrity, "hmac(sha512)", MAX_CIPHER_LEN);
	} else if (!strcmp(s, "cmac-aes")) {
		ks = 16;
		strncpy(integrity, "cmac(aes)", MAX_CIPHER_LEN);
	} else
		r = -EINVAL;

	if (integrity_key_size)
		*integrity_key_size = ks;

	return r;
}

int crypt_parse_pbkdf(const char *s, const char **pbkdf)
{
	const char *tmp = NULL;

	if (!s)
		return -EINVAL;

	if (!strcasecmp(s, CRYPT_KDF_PBKDF2))
		tmp = CRYPT_KDF_PBKDF2;
	else if (!strcasecmp(s, CRYPT_KDF_ARGON2I))
		tmp = CRYPT_KDF_ARGON2I;
	else if (!strcasecmp(s, CRYPT_KDF_ARGON2ID))
		tmp = CRYPT_KDF_ARGON2ID;

	if (!tmp)
		return -EINVAL;

	if (pbkdf)
		*pbkdf = tmp;

	return 0;
}

/*
 * Replacement for memset(s, 0, n) on stack that can be optimized out
 * Also used in safe allocations for explicit memory wipe.
 */
void crypt_memzero(void *s, size_t n)
{
	volatile uint8_t *p = (volatile uint8_t *)s;

	while(n--)
		*p++ = 0;
}

/* safe allocations */
void *crypt_safe_alloc(size_t size)
{
	struct safe_allocation *alloc;

	if (!size || size > (SIZE_MAX - offsetof(struct safe_allocation, data)))
		return NULL;

	/* round size to page */
	size = ((size + offsetof(struct safe_allocation, data)) + 4096-1) & (~(4096-1));
	if (!size || size > (SIZE_MAX - offsetof(struct safe_allocation, data)))
		return NULL;

	/*alloc = malloc(size + offsetof(struct safe_allocation, data));*/
	alloc = lkl_sys_mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (!alloc)
		return NULL;

	alloc->size = size;
	crypt_memzero(&alloc->data, size);

	/* coverity[leaked_storage] */
	return &alloc->data;
}

void crypt_safe_free(void *data)
{
	struct safe_allocation *alloc;

	if (!data)
		return;

	alloc = (struct safe_allocation *)
		((char *)data - offsetof(struct safe_allocation, data));
	size_t size = alloc->size;

	crypt_memzero(data, alloc->size);

	alloc->size = 0x55aa55aa;
	/*free(alloc);*/
	lkl_sys_munmap((unsigned long) alloc, size);
}

void *crypt_safe_realloc(void *data, size_t size)
{
	struct safe_allocation *alloc;
	void *new_data;

	new_data = crypt_safe_alloc(size);

	if (new_data && data) {

		alloc = (struct safe_allocation *)
			((char *)data - offsetof(struct safe_allocation, data));

		if (size > alloc->size)
			size = alloc->size;

		memcpy(new_data, data, size);
	}

	crypt_safe_free(data);
	return new_data;
}

ssize_t crypt_hex_to_bytes(const char *hex, char **result, int safe_alloc)
{
	char buf[3] = "xx\0", *endp, *bytes;
	size_t i, len;

	len = strlen(hex);
	if (len % 2)
		return -EINVAL;
	len /= 2;

	bytes = safe_alloc ? crypt_safe_alloc(len) : malloc(len);
	if (!bytes)
		return -ENOMEM;

	for (i = 0; i < len; i++) {
		memcpy(buf, &hex[i * 2], 2);
		bytes[i] = strtoul(buf, &endp, 16);
		if (endp != &buf[2]) {
			safe_alloc ? crypt_safe_free(bytes) : free(bytes);
			return -EINVAL;
		}
	}
	*result = bytes;
	return i;
}
