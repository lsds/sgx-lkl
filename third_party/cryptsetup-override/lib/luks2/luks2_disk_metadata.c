/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2018, Milan Broz. All rights reserved.
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

#include <assert.h>
#include <sys/mman.h>

#include "luks2_internal.h"
#include "lkl_host.h"

/*
 * Helper functions
 */
json_object *parse_json_len(const char *json_area, int length, int *end_offset)
{
	json_object *jobj;
	struct json_tokener *jtok;

	if (!json_area || length <= 0)
		return NULL;

	jtok = json_tokener_new();
	if (!jtok) {
		log_dbg("ERROR: Failed to init json tokener");
		return NULL;
	}

	jobj = json_tokener_parse_ex(jtok, json_area, length);
	if (!jobj)
		log_dbg("ERROR: Failed to parse json data (%d): %s",
			json_tokener_get_error(jtok),
			json_tokener_error_desc(json_tokener_get_error(jtok)));
	else
		*end_offset = jtok->char_offset;

	json_tokener_free(jtok);

	return jobj;
}

static void log_dbg_checksum(const uint8_t *csum, const char *csum_alg, const char *info)
{
	char csum_txt[2*LUKS2_CHECKSUM_L+1];
	int i;

	for (i = 0; i < crypt_hash_size(csum_alg); i++)
		snprintf(&csum_txt[i*2], 3, "%02hhx", (const char)csum[i]);
	csum_txt[i*2+1] = '\0'; /* Just to be safe, sprintf should write \0 there. */

	log_dbg("Checksum:%s (%s)", &csum_txt[0], info);
}

/*
 * Calculate hash (checksum) of |LUKS2_bin|LUKS2_JSON_area| from in-memory structs.
 * LUKS2 on-disk header contains uniques salt both for primary and secondary header.
 * Checksum is always calculated with zeroed checksum field in binary header.
 */
static int hdr_checksum_calculate(const char *alg, struct luks2_hdr_disk *hdr_disk,
				  const char *json_area, size_t json_len)
{
	struct crypt_hash *hd = NULL;
	int r;

	if (crypt_hash_size(alg) <= 0 || crypt_hash_init(&hd, alg))
		return -EINVAL;

	/* Binary header, csum zeroed. */
	r = crypt_hash_write(hd, (char*)hdr_disk, LUKS2_HDR_BIN_LEN);

	/* JSON area (including unused space) */
	if (!r)
		r = crypt_hash_write(hd, json_area, json_len);

	if (!r)
		r = crypt_hash_final(hd, (char*)hdr_disk->csum, crypt_hash_size(alg));

	crypt_hash_destroy(hd);
	return r;
}

/*
 * Compare hash (checksum) of on-disk and in-memory header.
 */
static int hdr_checksum_check(const char *alg, struct luks2_hdr_disk *hdr_disk,
			      const char *json_area, size_t json_len)
{
	struct luks2_hdr_disk hdr_tmp;
	int r;

	if (crypt_hash_size(alg) <= 0)
		return -EINVAL;

	/* Copy header and zero checksum. */
	memcpy(&hdr_tmp, hdr_disk, LUKS2_HDR_BIN_LEN);
	memset(&hdr_tmp.csum, 0, sizeof(hdr_tmp.csum));

	r = hdr_checksum_calculate(alg, &hdr_tmp, json_area, json_len);
	if (r < 0)
		return r;

	log_dbg_checksum(hdr_disk->csum, alg, "on-disk");
	log_dbg_checksum(hdr_tmp.csum, alg, "in-memory");

	if (memcmp(hdr_tmp.csum, hdr_disk->csum, crypt_hash_size(alg)))
		return -EINVAL;

	return 0;
}

/*
 * Convert header from on-disk format to in-memory struct
 */
static void hdr_from_disk(struct luks2_hdr_disk *hdr_disk1,
			  struct luks2_hdr_disk *hdr_disk2,
			  struct luks2_hdr *hdr,
			  int secondary)
{
	hdr->version  = be16_to_cpu(hdr_disk1->version);
	hdr->hdr_size = be64_to_cpu(hdr_disk1->hdr_size);
	hdr->seqid    = be64_to_cpu(hdr_disk1->seqid);

	memcpy(hdr->label, hdr_disk1->label, LUKS2_LABEL_L);
	hdr->label[LUKS2_LABEL_L - 1] = '\0';
	memcpy(hdr->subsystem, hdr_disk1->subsystem, LUKS2_LABEL_L);
	hdr->subsystem[LUKS2_LABEL_L - 1] = '\0';
	memcpy(hdr->checksum_alg, hdr_disk1->checksum_alg, LUKS2_CHECKSUM_ALG_L);
	hdr->checksum_alg[LUKS2_CHECKSUM_ALG_L - 1] = '\0';
	memcpy(hdr->uuid, hdr_disk1->uuid, LUKS2_UUID_L);
	hdr->uuid[LUKS2_UUID_L - 1] = '\0';

	if (secondary) {
		memcpy(hdr->salt1, hdr_disk2->salt, LUKS2_SALT_L);
		memcpy(hdr->salt2, hdr_disk1->salt, LUKS2_SALT_L);
	} else {
		memcpy(hdr->salt1, hdr_disk1->salt, LUKS2_SALT_L);
		memcpy(hdr->salt2, hdr_disk2->salt, LUKS2_SALT_L);
	}
}

/*
 * Convert header from in-memory struct to on-disk format
 */
static void hdr_to_disk(struct luks2_hdr *hdr,
			struct luks2_hdr_disk *hdr_disk,
			int secondary, uint64_t offset)
{
	assert(((char*)&(hdr_disk->_padding4096) - (char*)&(hdr_disk->magic)) == 512);

	memset(hdr_disk, 0, LUKS2_HDR_BIN_LEN);

	memcpy(&hdr_disk->magic, secondary ? LUKS2_MAGIC_2ND : LUKS2_MAGIC_1ST, LUKS2_MAGIC_L);
	hdr_disk->version     = cpu_to_be16(hdr->version);
	hdr_disk->hdr_size    = cpu_to_be64(hdr->hdr_size);
	hdr_disk->hdr_offset  = cpu_to_be64(offset);
	hdr_disk->seqid       = cpu_to_be64(hdr->seqid);

	strncpy(hdr_disk->label, hdr->label, LUKS2_LABEL_L);
	hdr_disk->label[LUKS2_LABEL_L - 1] = '\0';
	strncpy(hdr_disk->subsystem, hdr->subsystem, LUKS2_LABEL_L);
	hdr_disk->subsystem[LUKS2_LABEL_L - 1] = '\0';
	strncpy(hdr_disk->checksum_alg, hdr->checksum_alg, LUKS2_CHECKSUM_ALG_L);
	hdr_disk->checksum_alg[LUKS2_CHECKSUM_ALG_L - 1] = '\0';
	strncpy(hdr_disk->uuid, hdr->uuid, LUKS2_UUID_L);
	hdr_disk->uuid[LUKS2_UUID_L - 1] = '\0';

	memcpy(hdr_disk->salt, secondary ? hdr->salt2 : hdr->salt1, LUKS2_SALT_L);
}

/*
 * Sanity checks before checksum is validated
 */
static int hdr_disk_sanity_check_pre(struct luks2_hdr_disk *hdr,
				     size_t *hdr_json_size, int secondary,
				     uint64_t offset)
{
	if (memcmp(hdr->magic, secondary ? LUKS2_MAGIC_2ND : LUKS2_MAGIC_1ST, LUKS2_MAGIC_L))
		return -EINVAL;

	if (be16_to_cpu(hdr->version) != 2) {
		log_dbg("Unsupported LUKS2 header version %u.", be16_to_cpu(hdr->version));
		return -EINVAL;
	}

	if (offset != be64_to_cpu(hdr->hdr_offset)) {
		log_dbg("LUKS2 offset 0x%04x on device differs to expected offset 0x%04x.",
			(unsigned)be64_to_cpu(hdr->hdr_offset), (unsigned)offset);
		return -EINVAL;
	}

	/* FIXME: sanity check checksum alg. */

	log_dbg("LUKS2 header version %u of size %u bytes, checksum %s.",
		(unsigned)be16_to_cpu(hdr->version), (unsigned)be64_to_cpu(hdr->hdr_size),
		hdr->checksum_alg);

	*hdr_json_size = be64_to_cpu(hdr->hdr_size) - LUKS2_HDR_BIN_LEN;
	return 0;
}

/*
 * Read LUKS2 header from disk at specific offset.
 */
static int hdr_read_disk(struct device *device, struct luks2_hdr_disk *hdr_disk,
			 char **json_area, size_t *json_area_len, uint64_t offset, int secondary)
{
	size_t hdr_json_size = 0;
	int devfd = -1, r;

	log_dbg("Trying to read %s LUKS2 header at offset %" PRIu64 ".",
		secondary ? "secondary" : "primary", offset);

	devfd = device_open_locked(device, O_RDONLY);
	if (devfd < 0)
		return devfd == -1 ? -EIO : devfd;

	/*
	 * Read binary header and run sanity check before reading
	 * JSON area and validating checksum.
	 */
	if (read_lseek_blockwise(devfd, device_block_size(device),
				 device_alignment(device), hdr_disk,
				 LUKS2_HDR_BIN_LEN, offset) != LUKS2_HDR_BIN_LEN) {
		close(devfd);
		return -EIO;
	}

	r = hdr_disk_sanity_check_pre(hdr_disk, &hdr_json_size, secondary, offset);
	if (r < 0) {
		close(devfd);
		return r;
	}

	/*
	 * Allocate and read JSON area. Always the whole area must be read.
	 */
	/**json_area = malloc(hdr_json_size);*/
	*json_area = lkl_sys_mmap(NULL, hdr_json_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (!*json_area) {
		close(devfd);
		return -ENOMEM;
	}

	*json_area_len = hdr_json_size;

	if (read_lseek_blockwise(devfd, device_block_size(device),
				 device_alignment(device), *json_area, hdr_json_size,
				 offset + LUKS2_HDR_BIN_LEN) != (ssize_t)hdr_json_size) {
		close(devfd);
		/*free(*json_area);*/
		lkl_sys_munmap((unsigned long) *json_area, hdr_json_size);
		*json_area = NULL;
		return -EIO;
	}

	close(devfd);

	/*
	 * Calculate and validate checksum and zero it afterwards.
	 */
	if (hdr_checksum_check(hdr_disk->checksum_alg, hdr_disk,
				*json_area, hdr_json_size)) {
		log_dbg("LUKS2 header checksum error (offset %" PRIu64 ").", offset);
		r = -EINVAL;
	}
	memset(hdr_disk->csum, 0, LUKS2_CHECKSUM_L);

	return r;
}

/*
 * Write LUKS2 header to disk at specific offset.
 */
static int hdr_write_disk(struct device *device, struct luks2_hdr *hdr,
		   const char *json_area, int secondary)
{
	struct luks2_hdr_disk hdr_disk;
	uint64_t offset = secondary ? hdr->hdr_size : 0;
	size_t hdr_json_len;
	int devfd = -1, r;

	log_dbg("Trying to write LUKS2 header (%zu bytes) at offset %" PRIu64 ".",
		hdr->hdr_size, offset);

	/* FIXME: read-only device silent fail? */

	devfd = device_open_locked(device, O_RDWR);
	if (devfd < 0)
		return devfd == -1 ? -EINVAL : devfd;

	hdr_json_len = hdr->hdr_size - LUKS2_HDR_BIN_LEN;

	hdr_to_disk(hdr, &hdr_disk, secondary, offset);

	/*
	 * Write header without checksum but with proper seqid.
	 */
	if (write_lseek_blockwise(devfd, device_block_size(device),
				  device_alignment(device), (char *)&hdr_disk,
				  LUKS2_HDR_BIN_LEN, offset) < (ssize_t)LUKS2_HDR_BIN_LEN) {
		close(devfd);
		return -EIO;
	}

	/*
	 * Write json area.
	 */
	if (write_lseek_blockwise(devfd, device_block_size(device),
				  device_alignment(device),
				  CONST_CAST(char*)json_area, hdr_json_len,
				  LUKS2_HDR_BIN_LEN + offset) < (ssize_t)hdr_json_len) {
		close(devfd);
		return -EIO;
	}

	/*
	 * Calculate checksum and write header with checksum.
	 */
	r = hdr_checksum_calculate(hdr_disk.checksum_alg, &hdr_disk,
				   json_area, hdr_json_len);
	if (r < 0) {
		close(devfd);
		return r;
	}
	log_dbg_checksum(hdr_disk.csum, hdr_disk.checksum_alg, "in-memory");

	if (write_lseek_blockwise(devfd, device_block_size(device),
				  device_alignment(device), (char *)&hdr_disk,
				  LUKS2_HDR_BIN_LEN, offset) < (ssize_t)LUKS2_HDR_BIN_LEN)
		r = -EIO;

	close(devfd);
	return r;
}

static int LUKS2_check_device_size(struct crypt_device *cd, struct device *device,
				   uint64_t hdr_size, int falloc)
{
	uint64_t dev_size;

	if (device_size(device, &dev_size)) {
		log_dbg("Cannot get device size for device %s.", device_path(device));
		return -EIO;
	}

	log_dbg("Device size %" PRIu64 ", header size %"
		PRIu64 ".", dev_size, hdr_size);

	if (hdr_size > dev_size) {
		/* If it is header file, increase its size */
		if (falloc && !device_fallocate(device, hdr_size))
			return 0;

		log_err(cd, _("Device %s is too small. (LUKS2 requires at least %" PRIu64 " bytes.)\n"),
			device_path(device), hdr_size);
		return -EINVAL;
	}

	return 0;
}

/*
 * Convert in-memory LUKS2 header and write it to disk.
 * This will increase sequence id, write both header copies and calculate checksum.
 */
int LUKS2_disk_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr, struct device *device)
{
	char *json_area;
	const char *json_text;
	size_t json_area_len;
	int r;

	if (hdr->version != 2) {
		log_dbg("Unsupported LUKS2 header version (%u).", hdr->version);
		return -EINVAL;
	}

	if (hdr->hdr_size != LUKS2_HDR_16K_LEN) {
		log_dbg("Unsupported LUKS2 header size (%zu).", hdr->hdr_size);
		return -EINVAL;
	}

	r = LUKS2_check_device_size(cd, crypt_metadata_device(cd), LUKS2_hdr_and_areas_size(hdr->jobj), 1);
	if (r)
		return r;

	/*
	 * Allocate and zero JSON area (of proper header size).
	 */
	json_area_len = hdr->hdr_size - LUKS2_HDR_BIN_LEN;
	/*json_area = malloc(json_area_len);*/
	json_area = lkl_sys_mmap(NULL, json_area_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (!json_area)
		return -ENOMEM;
	memset(json_area, 0, json_area_len);

	/*
	 * Generate text space-efficient JSON representation to json area.
	 */
	json_text = json_object_to_json_string_ext(hdr->jobj, JSON_C_TO_STRING_PLAIN);
	if (!json_text || !*json_text) {
		log_dbg("Cannot parse JSON object to text representation.");
		/*free(json_area);*/
		lkl_sys_munmap((unsigned long) json_area, json_area_len);
		return -ENOMEM;
	}
	if (strlen(json_text) > (json_area_len - 1)) {
		log_dbg("JSON is too large (%zu > %zu).", strlen(json_text), json_area_len);
		/*free(json_area);*/
		lkl_sys_munmap((unsigned long) json_area, json_area_len);
		return -EINVAL;
	}
	strncpy(json_area, json_text, json_area_len);

	/* Increase sequence id before writing it to disk. */
	hdr->seqid++;

	r = device_write_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire write device lock.\n"));
		/*free(json_area);*/
		lkl_sys_munmap((unsigned long) json_area, json_area_len);
		return r;
	}

	/* Write primary and secondary header */
	r = hdr_write_disk(device, hdr, json_area, 0);
	if (!r)
		r = hdr_write_disk(device, hdr, json_area, 1);

	if (r)
		log_dbg("LUKS2 header write failed (%d).", r);

	device_write_unlock(device);

	/* FIXME: try recovery here? */

	/*free(json_area);*/
	lkl_sys_munmap((unsigned long) json_area, json_area_len);
	return r;
}

static int validate_json_area(const char *json_area, int start, int length)
{
	char c;

	/* Enforce there are no needless opening bytes */
	if (*json_area != '{') {
		log_dbg("ERROR: Opening character must be left curly bracket: '{'.");
		return -EINVAL;
	}

	if (start >= length) {
		log_dbg("ERROR: Missing trailing null byte beyond parsed json data string.");
		return -EINVAL;
	}

	/*
	 * TODO:
	 *	validate there are legal json format characters between
	 *	'json_area' and 'json_area + start'
	 */

	do {
		c = *(json_area + start);
		if (c != '\0') {
			log_dbg("ERROR: Forbidden ascii code 0x%02hhx found beyond json data string at offset %d.",
				c, start);
			return -EINVAL;
		}
	} while (++start < length);

	return 0;
}

static int validate_luks2_json_object(json_object *jobj_hdr)
{
	int r;

	/* we require top level object to be of json_type_object */
	r = !json_object_is_type(jobj_hdr, json_type_object);
	if (r) {
		log_dbg("ERROR: Resulting object is not a json object type");
		return r;
	}

	r = LUKS2_hdr_validate(jobj_hdr);
	if (r)
		log_dbg("ERROR: LUKS2 validation failed");

	return r;
}

static json_object *parse_and_validate_json(const char *json_area, int length)
{
	int offset, r;
	json_object *jobj = parse_json_len(json_area, length, &offset);

	if (!jobj)
		return NULL;

	/* successful parse_json_len must not return offset <= 0 */
	assert(offset > 0);

	r = validate_json_area(json_area, offset, length);
	if (!r)
		r = validate_luks2_json_object(jobj);

	if (r) {
		json_object_put(jobj);
		jobj = NULL;
	}

	return jobj;
}

/*
 * Read and convert on-disk LUKS2 header to in-memory representation..
 * Try to do recovery if on-disk state is not consistent.
 */
int LUKS2_disk_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr,
			struct device *device, int do_recovery)
{
	enum { HDR_OK, HDR_OBSOLETE, HDR_FAIL, HDR_FAIL_IO } state_hdr1, state_hdr2;
	struct luks2_hdr_disk hdr_disk1, hdr_disk2;
	char *json_area1 = NULL, *json_area2 = NULL;
	size_t json_area1_len = 0, json_area2_len = 0;
	json_object *jobj_hdr1 = NULL, *jobj_hdr2 = NULL;
	int i, r;
	uint64_t hdr_size;

	if (do_recovery && !crypt_metadata_locking_enabled()) {
		do_recovery = 0;
		log_dbg("Disabling header auto-recovery due to locking being disabled.");
	}

	/*
	 * Read primary LUKS2 header (offset 0).
	 */
	state_hdr1 = HDR_FAIL;
	r = hdr_read_disk(device, &hdr_disk1, &json_area1, &json_area1_len, 0, 0);
	if (r == 0) {
		jobj_hdr1 = parse_and_validate_json(json_area1, be64_to_cpu(hdr_disk1.hdr_size) - LUKS2_HDR_BIN_LEN);
		state_hdr1 = jobj_hdr1 ? HDR_OK : HDR_OBSOLETE;
	} else if (r == -EIO)
		state_hdr1 = HDR_FAIL_IO;

	/*
	 * Read secondary LUKS2 header (follows primary).
	 */
	state_hdr2 = HDR_FAIL;
	if (state_hdr1 != HDR_FAIL && state_hdr1 != HDR_FAIL_IO) {
		r = hdr_read_disk(device, &hdr_disk2, &json_area2, &json_area2_len, be64_to_cpu(hdr_disk1.hdr_size), 1);
		if (r == 0) {
			jobj_hdr2 = parse_and_validate_json(json_area2, be64_to_cpu(hdr_disk2.hdr_size) - LUKS2_HDR_BIN_LEN);
			state_hdr2 = jobj_hdr2 ? HDR_OK : HDR_OBSOLETE;
		} else if (r == -EIO)
			state_hdr2 = HDR_FAIL_IO;
	} else {
		/*
		 * No header size, check all known offsets.
		 */
		for (r = -EINVAL,i = 2; r < 0 && i <= 1024; i <<= 1)
			r = hdr_read_disk(device, &hdr_disk2, &json_area2, &json_area2_len, i * 4096, 1);

		if (r == 0) {
			jobj_hdr2 = parse_and_validate_json(json_area2, be64_to_cpu(hdr_disk2.hdr_size) - LUKS2_HDR_BIN_LEN);
			state_hdr2 = jobj_hdr2 ? HDR_OK : HDR_OBSOLETE;
		} else if (r == -EIO)
			state_hdr2 = HDR_FAIL_IO;
	}

	/*
	 * Check sequence id if both headers are read correctly.
	 */
	if (state_hdr1 == HDR_OK && state_hdr2 == HDR_OK) {
		if (be64_to_cpu(hdr_disk1.seqid) > be64_to_cpu(hdr_disk2.seqid))
			state_hdr2 = HDR_OBSOLETE;
		else if (be64_to_cpu(hdr_disk1.seqid) < be64_to_cpu(hdr_disk2.seqid))
			state_hdr1 = HDR_OBSOLETE;
	}

	/* check header with keyslots to fit the device */
	if (state_hdr1 == HDR_OK)
		hdr_size = LUKS2_hdr_and_areas_size(jobj_hdr1);
	else if (state_hdr2 == HDR_OK)
		hdr_size = LUKS2_hdr_and_areas_size(jobj_hdr2);
	else {
		r = (state_hdr1 == HDR_FAIL_IO && state_hdr2 == HDR_FAIL_IO) ? -EIO : -EINVAL;
		goto err;
	}

	r = LUKS2_check_device_size(cd, device, hdr_size, 0);
	if (r)
		goto err;

	/*
	 * Try to rewrite (recover) bad header. Always regenerate salt for bad header.
	 */
	if (state_hdr1 == HDR_OK && state_hdr2 != HDR_OK) {
		log_dbg("Secondary LUKS2 header requires recovery.");

		if (do_recovery) {
			memcpy(&hdr_disk2, &hdr_disk1, LUKS2_HDR_BIN_LEN);
			r = crypt_random_get(NULL, (char*)hdr_disk2.salt, sizeof(hdr_disk2.salt), CRYPT_RND_SALT);
			if (r)
				log_dbg("Cannot generate master salt.");
			else {
				hdr_from_disk(&hdr_disk1, &hdr_disk2, hdr, 0);
				r = hdr_write_disk(device, hdr, json_area1, 1);
			}
			if (r)
				log_dbg("Secondary LUKS2 header recovery failed.");
		}
	} else if (state_hdr1 != HDR_OK && state_hdr2 == HDR_OK) {
		log_dbg("Primary LUKS2 header requires recovery.");

		if (do_recovery) {
			memcpy(&hdr_disk1, &hdr_disk2, LUKS2_HDR_BIN_LEN);
			r = crypt_random_get(NULL, (char*)hdr_disk1.salt, sizeof(hdr_disk1.salt), CRYPT_RND_SALT);
			if (r)
				log_dbg("Cannot generate master salt.");
			else {
				hdr_from_disk(&hdr_disk2, &hdr_disk1, hdr, 1);
				r = hdr_write_disk(device, hdr, json_area2, 0);
			}
			if (r)
				log_dbg("Primary LUKS2 header recovery failed.");
		}
	}

	/*free(json_area1);*/
	lkl_sys_munmap((unsigned long) json_area1, json_area1_len);
	json_area1 = NULL;
	/*free(json_area2);*/
	lkl_sys_munmap((unsigned long) json_area2, json_area2_len);
	json_area2 = NULL;

	/* wrong lock for write mode during recovery attempt */
	if (r == -EAGAIN)
		goto err;

	/*
	 * Even if status is failed, the second header includes salt.
	 */
	if (state_hdr1 == HDR_OK) {
		hdr_from_disk(&hdr_disk1, &hdr_disk2, hdr, 0);
		hdr->jobj = jobj_hdr1;
		json_object_put(jobj_hdr2);
	} else if (state_hdr2 == HDR_OK) {
		hdr_from_disk(&hdr_disk2, &hdr_disk1, hdr, 1);
		hdr->jobj = jobj_hdr2;
		json_object_put(jobj_hdr1);
	}

	/*
	 * FIXME: should this fail? At least one header was read correctly.
	 * r = (state_hdr1 == HDR_FAIL_IO || state_hdr2 == HDR_FAIL_IO) ? -EIO : -EINVAL;
	 */
	return 0;
err:
	log_dbg("LUKS2 header read failed (%d).", r);

	free(json_area1);
	free(json_area2);
	json_object_put(jobj_hdr1);
	json_object_put(jobj_hdr2);
	hdr->jobj = NULL;
	return r;
}

int LUKS2_hdr_version_unlocked(struct crypt_device *cd, const char *backup_file)
{
	struct {
		char magic[LUKS2_MAGIC_L];
		uint16_t version;
	}  __attribute__ ((packed)) hdr;
	struct device *device = NULL;
	int r = 0, devfd = -1, flags;

	if (!backup_file)
		device = crypt_metadata_device(cd);
	else if (device_alloc(&device, backup_file) < 0)
		return 0;

	if (!device)
		return 0;

	flags = O_RDONLY;
	if (device_direct_io(device))
		flags |= O_DIRECT;

	devfd = open(device_path(device), flags);
	if (devfd < 0)
		goto err;

	if ((read_lseek_blockwise(devfd, device_block_size(device),
	     device_alignment(device), &hdr, sizeof(hdr), 0) == sizeof(hdr)) &&
	    !memcmp(hdr.magic, LUKS2_MAGIC_1ST, LUKS2_MAGIC_L))
		r = (int)be16_to_cpu(hdr.version);
err:
	if (devfd != -1)
		close(devfd);

	if (backup_file)
		device_free(device);

	return r;
}
