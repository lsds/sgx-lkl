#include <libdevmapper.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

#include "dm.h"
#include "vic.h"
#include "raise.h"
#include "strings.h"
#include "loop.h"
#include "integrity.h"
#include "hexdump.h"
#include "malloc.h"
#include "trace.h"
#include "uuid.h"

// #define TRACE_TARGET

#define DM_UUID_LEN 129

// #define USE_UDEV

static vic_result_t _format_dev_uuid(
    char dev_uuid[DM_UUID_LEN],
    const char* prefix,
    const char* uuid,
    const char* dm_name)
{
    vic_result_t result = VIC_OK;
    uint32_t x1;
    uint32_t x2;
    uint32_t x3;
    uint32_t x4;
    uint64_t x5;
    int n;

    if (!dev_uuid || !vic_uuid_valid(uuid) || !dm_name)
        RAISE(VIC_BAD_PARAMETER);

    n = sscanf(uuid, "%08x-%04x-%04x-%04x-%012lx", &x1, &x2, &x3, &x4, &x5);
    if (n != 5)
        RAISE(VIC_BAD_UUID);

    n = snprintf(dev_uuid, DM_UUID_LEN, "%s-%08x%04x%04x%04x%012lx-%s",
        prefix, x1, x2, x3, x4, x5, dm_name);
    if (n >= DM_UUID_LEN)
        RAISE(VIC_BUFFER_TOO_SMALL);

done:
    return result;
}

vic_result_t vic_dm_create_crypt(
    const char* prefix,
    const char* name,
    const char* path,
    const char* uuid,
    uint64_t start,
    uint64_t size,
    const char* integrity,
    const char* cipher,
    const uint8_t* key,
    uint64_t key_bytes,
    uint64_t iv_offset,
    uint64_t offset)
{
    vic_result_t result = VIC_OK;
    char params[1024];
    struct dm_task* dmt = NULL;
    char* hexkey = NULL;
    char dev[PATH_MAX];
#ifdef USE_UDEV
    int sync;
    uint32_t cookie = 0;
#endif

    /* Reject invalid parameters */
    if (!name || !path || !uuid || !integrity || !cipher || !key || !key_bytes)
        RAISE(VIC_BAD_PARAMETER);

    /* If not a block device, then map to a loopback device */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            RAISE(VIC_FAILED);

        if (S_ISBLK(st.st_mode))
        {
            if (vic_strlcpy(dev, path, PATH_MAX) >= PATH_MAX)
                RAISE(VIC_PATH_TOO_LONG);
        }
        else
        {
            if (vic_loop_attach(path, 0, false, false, dev) != 0)
                RAISE(VIC_FAILED_TO_GET_LOOP_DEVICE);
        }
    }

    /* Convert the key to hex */
    {
        if (!(hexkey = vic_malloc((key_bytes * 2) + 1)))
            RAISE(VIC_OUT_OF_MEMORY);

        for (size_t i = 0, j = 0; i < key_bytes; i++, j += 2)
            snprintf(&hexkey[j], 3, "%02x", key[i]);
    }

    /* Format the params */
    {
        int n;

        if (*integrity)
        {
            char capi[256];
            size_t tag_size = vic_integrity_tag_size(integrity);

            if (tag_size == (size_t)-1)
                RAISE(VIC_UNEXPECTED);

            /* ATTN: support other ciphers in integrity mode */
            if (strcmp(cipher, "aes-xts-plain64") != 0)
                RAISE(VIC_UNSUPPORTED_CIPHER);

            snprintf(capi, sizeof(capi),
                "capi:authenc(%s,xts(aes))-plain64", integrity);

            n = snprintf(params, sizeof(params),
                "%s %s %lu %s %lu 1 integrity:%lu:aead",
                capi,
                hexkey,
                iv_offset,
                dev,
                offset,
                tag_size);
        }
        else
        {
            n = snprintf(params, sizeof(params),
                "%s %s %lu %s %lu",
                cipher,
                hexkey,
                iv_offset,
                dev,
                offset);
        }

        if (n <= 0 || (size_t)n >= sizeof(params))
            RAISE(VIC_BUFFER_TOO_SMALL);
    }

    /* Create the device-mapper task object */
    if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
        RAISE(VIC_FAILED);

    /* Set the device-mapper name */
    if (!dm_task_set_name(dmt, name))
        RAISE(VIC_FAILED);

    /* Set the UUID */
    {
        char dev_uuid[DM_UUID_LEN] = {0};

        CHECK(_format_dev_uuid(dev_uuid, prefix, uuid, name));

        if (!dm_task_set_uuid(dmt, dev_uuid))
            RAISE(VIC_FAILED);
    }

#ifdef TRACE_TARGET
    printf("DM-NAME: %s\n", name);
    printf("TARGET: start{%lu} size{%lu} target{%s} params{%s}\n",
        start, size, "crypt", params);
#endif

    /* Set the target */
    if (!dm_task_add_target(dmt, start, size, "crypt", params))
        RAISE(VIC_FAILED);

#ifdef USE_UDEV
    /* Determine whether sync support is available */
    if ((sync = dm_udev_get_sync_support()))
    {
        uint16_t udev_flags = DM_UDEV_DISABLE_LIBRARY_FALLBACK;
        dm_task_set_cookie(dmt, &cookie, udev_flags);
    }
#endif

    /* Run the task to create the new target type */
    if (!dm_task_run(dmt))
        RAISE(VIC_FAILED);

    /* Verify that the target now exists */
    {
        struct dm_info dmi;

        if (!dm_task_get_info(dmt, &dmi) || !dmi.exists)
            RAISE(VIC_FAILED);
    }

#ifdef USE_UDEV
    if (sync)
        dm_udev_wait(cookie);
#endif

done:

    if (hexkey)
        vic_free(hexkey);

    if (dmt)
    {
        dm_task_destroy(dmt);
        dm_task_update_nodes();
    }

    dm_lib_release();

    return result;
}

vic_result_t vic_dm_create_integrity(
    const char* name,
    const char* path,
    uint64_t start,
    uint64_t size,
    uint64_t offset,
    char mode,
    const char* integrity)
{
    vic_result_t result = VIC_OK;
    char params[1024];
    struct dm_task* dmt = NULL;
    char* hexkey = NULL;
    char dev[PATH_MAX];

    /* Reject invalid parameters */
    if (!name || !path)
        RAISE(VIC_BAD_PARAMETER);

    /* If not a block device, then map to a loopback device */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            RAISE(VIC_FAILED);

        if (S_ISBLK(st.st_mode))
        {
            if (vic_strlcpy(dev, path, PATH_MAX) >= PATH_MAX)
                RAISE(VIC_PATH_TOO_LONG);
        }
        else
        {
            if (vic_loop_attach(path, 0, false, false, dev) != 0)
                RAISE(VIC_FAILED_TO_GET_LOOP_DEVICE);
        }
    }

    /* Format the params */
    {
        size_t tag_size = vic_integrity_tag_size(integrity);

        if (tag_size == (size_t)-1)
            RAISE(VIC_UNEXPECTED);

        /* ATTN: hard-coded block size */
        uint64_t block_size = 512;

        int n = snprintf(
            params,
            sizeof(params),
            "%s %lu %lu %c 1 block_size:%lu",
            dev,
            offset,
            tag_size,
            mode,
            block_size);

        if (n <= 0 || (size_t)n >= sizeof(params))
            RAISE(VIC_BUFFER_TOO_SMALL);
    }

    /* Create the device-mapper task object */
    if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
        RAISE(VIC_FAILED);

    /* Set the device-mapper name */
    if (!dm_task_set_name(dmt, name))
        RAISE(VIC_FAILED);

#ifdef TRACE_TARGET
    printf("DM-NAME: %s\n", name);
    printf("TARGET: start{%lu} size{%lu} target{%s} params{%s}\n",
        start, size, "integrity", params);
#endif

    /* Set the target */
    if (!dm_task_add_target(dmt, start, size, "integrity", params))
        RAISE(VIC_FAILED);

    /* Run the task to create the new target type */
    if (!dm_task_run(dmt))
        RAISE(VIC_FAILED);

    /* Verify that the target now exists */
    {
        struct dm_info dmi;

        if (!dm_task_get_info(dmt, &dmi) || !dmi.exists)
            RAISE(VIC_FAILED);
    }

done:

    if (hexkey)
        vic_free(hexkey);

    if (dmt)
    {
        dm_task_destroy(dmt);
        dm_task_update_nodes();
    }

    dm_lib_release();

    return result;
}

vic_result_t vic_dm_create_verity(
    const char* dm_name,
    const char* data_dev,
    const char* hash_dev,
    size_t data_block_size,
    size_t hash_block_size,
    size_t num_blocks,
    uint32_t version,
    uint32_t hash_offset,
    const char* hash_alg,
    const uint8_t* root_digest,
    size_t root_digest_size,
    const uint8_t* salt,
    size_t salt_size)
{
    vic_result_t result = VIC_OK;
    char params[2048];
    struct dm_task* dmt = NULL;
    char data_dev_path[PATH_MAX];
    char hash_dev_path[PATH_MAX];
    char* root_digest_ascii = NULL;
    char* salt_ascii = NULL;
    const size_t start = 0;
    size_t size;
    const char target[] = "verity";

    /* Reject invalid parameters */
    if (!dm_name || !data_dev || !hash_dev || !data_block_size ||
        !hash_block_size || !num_blocks || !hash_alg || !root_digest ||
        !root_digest_size || !salt || !salt_size)
    {
        RAISE(VIC_BAD_PARAMETER);
    }

    /* Map data device to a loopback device (if not a block device already) */
    CHECK(vic_loop_map(data_dev, data_dev_path, true));

    /* Map hash device to a loopback device (if not a block device already) */
    CHECK(vic_loop_map(hash_dev, hash_dev_path, true));

    /* Convert root digest to ASCII format */
    CHECK(vic_bin_to_ascii(root_digest, root_digest_size, &root_digest_ascii));

    /* Convert salt to ASCII format */
    CHECK(vic_bin_to_ascii(salt, salt_size, &salt_ascii));

    /* Calculate the size as 512-byte sectors */
    size = (num_blocks * data_block_size) / VIC_SECTOR_SIZE;

    /* Format the params */
    {
        int n = snprintf(
            params,
            sizeof(params),
            "%u "  /* version */
            "%s "  /* data_dev */
            "%s "  /* hash_dev */
            "%zu " /* data_block_size */
            "%zu " /* hash_block_size */
            "%zu " /* num_blocks */
            "%u "  /* hash_offset*/
            "%s "  /* hash_alg */
            "%s "  /* root_digest */
            "%s "  /* salt */
            "",
            version,
            data_dev_path,
            hash_dev_path,
            data_block_size,
            hash_block_size,
            num_blocks,
            hash_offset,
            hash_alg,
            root_digest_ascii,
            salt_ascii);

        if (n <= 0 || (size_t)n >= sizeof(params))
            RAISE(VIC_BUFFER_TOO_SMALL);
    }

    /* Create the device-mapper task object */
    if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
        RAISE(VIC_FAILED);

    /* Set the device-mapper name */
    if (!dm_task_set_name(dmt, dm_name))
        RAISE(VIC_FAILED);

    if (!dm_task_secure_data(dmt))
        RAISE(VIC_FAILED);

    if (!dm_task_set_ro(dmt))
        RAISE(VIC_FAILED);

#ifdef TRACE_TARGET
    printf("DM-NAME: %s\n", dm_name);
    printf("TARGET: start{%lu} size{%lu} target{%s} params{%s}\n",
        start, size, target, params);
#endif

    /* Set the target */
    if (!dm_task_add_target(dmt, start, size, target, params))
        RAISE(VIC_FAILED);

    /* Run the task to create the new target type */
    if (!dm_task_run(dmt))
        RAISE(VIC_FAILED);

    /* Verify that the target now exists */
    {
        struct dm_info dmi;

        if (!dm_task_get_info(dmt, &dmi) || !dmi.exists)
            RAISE(VIC_FAILED);
    }

done:

    if (root_digest_ascii)
        vic_free(root_digest_ascii);

    if (salt_ascii)
        vic_free(salt_ascii);

    if (dmt)
    {
        dm_task_destroy(dmt);
        dm_task_update_nodes();
    }

    dm_lib_release();

    return result;
}

vic_result_t vic_dm_remove(const char* name)
{
    vic_result_t result = VIC_OK;
    struct dm_task* dmt = NULL;
    const size_t max_retries = 10;

    if (!name)
        RAISE(VIC_BAD_PARAMETER);

    if (!(dmt = dm_task_create(DM_DEVICE_REMOVE)))
        RAISE(VIC_FAILED);

    if (!dm_task_set_name(dmt, name))
        RAISE(VIC_FAILED);

    /* Wait until the device is not busy (wait 1 second at most) */
    for (size_t i = 0; i < max_retries; i++)
    {
        if (dm_task_run(dmt))
        {
            struct timespec req;
            const uint64_t second = 1000000000;

            /* Sleep for 1/10th of a second */
            req.tv_sec = 0;
            req.tv_nsec = second / 10;
            nanosleep(&req, NULL);
            break;
        }
    }

done:

    if (dmt)
    {
        dm_task_destroy(dmt);
        dm_task_update_nodes();
    }

    dm_lib_release();

    return result;
}
