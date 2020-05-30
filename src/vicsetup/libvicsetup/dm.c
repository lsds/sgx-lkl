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

#if 1
#define TRACE_TARGET
#endif

#if 1
#define TRACE_IOCTL
#endif

/* ioctl() commands */
#define DM_VERSION_CMD 3241737472
#define DM_CREATE_CMD 3241737475
#define DM_RELOAD_CMD 3241737481
#define DM_RESUME_CMD 3241737478

#define DM_VERSION_INITIALIZER { 4, 0, 0 }
#define DM_MAX_TYPE_NAME 16
#define DM_NAME_LEN 128
#define DM_UUID_LEN 129
#define DM_DATA_SIZE 16384
#define DM_DATA_START (sizeof(struct dm_ioctl) - sizeof(struct dm_target))
#define DM_PARAMS_LEN 4096

#define DM_EXISTS_FLAG 0x00000004

#define DM_UEVENT_GENERATED_FLAG (1 << 13)

struct dm_target
{
    uint64_t sector_start;
    uint64_t length;
    int32_t status;
    uint32_t next;
    char target_type[DM_MAX_TYPE_NAME];
    char params[DM_PARAMS_LEN];
};

struct dm_ioctl
{
    uint32_t version[3];
    uint32_t data_size; /* DM_DATA_SIZE */
    uint32_t data_start; /* DM_DATA_START */
    uint32_t target_count;
    int32_t open_count;
    uint32_t flags;
    uint32_t event_nr;
    uint32_t padding;
    uint64_t dev;
    char name[DM_NAME_LEN];
    char uuid[DM_UUID_LEN];
    char data[7];
    struct dm_target target;
};

#ifdef TRACE_IOCTL
static void _dump_dm_ioctl(struct dm_ioctl* dmi)
{
    printf(
        "dm_ioctl\n"
        "{\n"
        "    version=%u.%u.%u\n"
        "    data_size=%u\n"
        "    data_start=%u\n"
        "    target_count=%u\n"
        "    open_count=%d\n"
        "    flags=%u\n"
        "    event_nr=%u\n"
        "    padding=%u\n"
        "    dev=%lu\n"
        "    name=%s\n"
        "    uuid=%s\n",
        dmi->version[0],
        dmi->version[1],
        dmi->version[2],
        dmi->data_size,
        dmi->data_start,
        dmi->target_count,
        dmi->open_count,
        dmi->flags,
        dmi->event_nr,
        dmi->padding,
        dmi->dev,
        dmi->name,
        dmi->uuid);

    if (dmi->target_count > 0)
    {
        printf(
            "    target.sector_start=%lu\n"
            "    target.length=%lu\n"
            "    target.status=%d\n"
            "    target.next=%u\n"
            "    target.target_type=%s\n"
            "    target.params=%s\n",
            dmi->target.sector_start,
            dmi->target.length,
            dmi->target.status,
            dmi->target.next,
            dmi->target.target_type,
            dmi->target.params);
    }

    printf("}\n");
}
#endif /* TRACE_IOCTL */

#ifndef USE_LIBDEVMAPPER
static int _ioctl(int fd, unsigned long request, struct dm_ioctl* dmi)
{
    int r;
#ifdef TRACE_IOCTL
    const char* name;
#endif

#ifdef TRACE_IOCTL
    switch(request)
    {
        case DM_VERSION_CMD:
            name = "version";
            break;
        case DM_CREATE_CMD:
            name = "create";
            break;
        case DM_RELOAD_CMD:
            name = "reload";
            break;
        case DM_RESUME_CMD:
            name = "resume";
            break;
        default:
            name = "unknown";
            break;
    }
#endif

#ifdef TRACE_IOCTL
    printf("**** before ioctl(%lu, %s)\n", request, name);
    _dump_dm_ioctl(dmi);
#endif

    r = ioctl(fd, request, dmi);

#ifdef TRACE_IOCTL
    printf("**** after ioctl(%s): r=%d errno=%d\n", name, r, errno);
    _dump_dm_ioctl(dmi);
#endif

    return r;
}
#endif /* USE_LIBDEVMAPPER */

static vic_result_t _update_dev_mapper_node(const char* name)
{
    vic_result_t result = VIC_OK;
    char path[PATH_MAX];
    mode_t mask;
    const mode_t mode = 0600;
    const uint32_t major = 253;
    const uint32_t minor = 0;
    const uid_t uid = 0;
    const gid_t gid = 0;
    dev_t dev = makedev(major, minor);

    STRLCPY(path, "/dev/mapper/");
    STRLCAT(path, name);

    mask = umask(0);

    if (mknod(path, S_IFBLK | mode, dev) < 0)
    {
        umask(mask);
        RAISE(VIC_FAILED);
    }

    umask(mask);

    if (chown(path, uid, gid) < 0)
        RAISE(VIC_FAILED);

done:
    return result;
}

#ifdef USE_LIBDEVMAPPER
vic_result_t vic_dm_create_crypt(
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
    if (!dm_task_set_uuid(dmt, uuid))
        RAISE(VIC_FAILED);

#ifdef TRACE_TARGET
    printf("TARGET: start{%lu} size{%lu} target{%s} params{%s}\n",
        start, size, "crypt", params);
#endif

    /* Set the target */
    if (!dm_task_add_target(dmt, start, size, "crypt", params))
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

    return result;
}
#endif /* USE_LIBDEVMAPPER */

#ifndef USE_LIBDEVMAPPER
vic_result_t vic_dm_create_crypt(
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
    char* hexkey = NULL;
    char dev[PATH_MAX];
    int ctl = -1;
    struct dm_ioctl* dmi = NULL;
    static const uint32_t dm_version[] = DM_VERSION_INITIALIZER;
    int r;

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

    /* Open the /dev/mapper/control device */
    if ((ctl = open("/dev/mapper/control", O_RDWR)) < 0)
        RAISE(VIC_OPEN_FAILED);

    /* Allocate instance of struct dm_ioctl */
    if (!(dmi = calloc(1, DM_DATA_SIZE)))
        RAISE(VIC_OUT_OF_MEMORY);

#ifdef TRACE_TARGET
    printf("TARGET: start{%lu} size{%lu} target{%s} params{%s}\n",
        start, size, "crypt", params);
#endif

    /* Perform DM_VERSION_CMD */
    {
        memset(dmi, 0, sizeof(struct dm_ioctl));
        memcpy(dmi->version, dm_version, sizeof(dmi->version));
        dmi->data_size = DM_DATA_SIZE;
        dmi->data_start = DM_DATA_START;
        dmi->flags = DM_EXISTS_FLAG;

        if ((r = _ioctl(ctl, DM_VERSION_CMD, dmi)) < 0)
            RAISE(VIC_IOCTL_FAILED);
    }

    /* Perform DM_CREATE_CMD */
    {
        size_t retries = 0;

        memset(dmi, 0, sizeof(struct dm_ioctl));
        memcpy(dmi->version, dm_version, sizeof(dmi->version));
        dmi->data_size = DM_DATA_SIZE;
        dmi->data_start = DM_DATA_START;
        dmi->flags = DM_EXISTS_FLAG;
        STRLCPY(dmi->name, name);
        STRLCPY(dmi->uuid, uuid);

retry:
        if ((r = _ioctl(ctl, DM_CREATE_CMD, dmi)) < 0)
        {
            if (errno == EBUSY && retries++ < 10)
            {
                printf("RETRY........\n");
                goto retry;
            }
            RAISE(VIC_IOCTL_FAILED);
        }
    }

    /* Perform DM_RELOAD_CMD */
    {
        size_t n;

        memset(dmi, 0, sizeof(struct dm_ioctl));
        memcpy(dmi->version, dm_version, sizeof(dmi->version));
        dmi->data_size = DM_DATA_SIZE;
        dmi->data_start = DM_DATA_START;
        dmi->target_count = 1;
        dmi->flags = DM_EXISTS_FLAG;
        STRLCPY(dmi->name, name);

        dmi->target.sector_start = start;
        dmi->target.length = size;
        STRLCPY(dmi->target.target_type, "crypt");
        n = STRLCPY(dmi->target.params, params);

        dmi->target.next = sizeof(struct dm_target) - DM_PARAMS_LEN + n;

        if ((r = _ioctl(ctl, DM_RELOAD_CMD, dmi)) < 0)
            RAISE(VIC_IOCTL_FAILED);
    }

    /* Perform DM_RESUME */
    {
        size_t n;

        memset(dmi, 0, sizeof(struct dm_ioctl));
        memcpy(dmi->version, dm_version, sizeof(dmi->version));
        dmi->data_size = DM_DATA_SIZE;
        dmi->data_start = DM_DATA_START;
        dmi->target_count = 1;
        dmi->flags = DM_EXISTS_FLAG;
        dmi->event_nr = 0;
        STRLCPY(dmi->name, name);

        dmi->target.sector_start = start;
        dmi->target.length = size;
        STRLCPY(dmi->target.target_type, "crypt");
        n = STRLCPY(dmi->target.params, params);

        dmi->target.next = sizeof(struct dm_target) - DM_PARAMS_LEN + n;

        if ((r = _ioctl(ctl, DM_RESUME_CMD, dmi)) < 0)
            RAISE(VIC_IOCTL_FAILED);
    }

    close(ctl);
    ctl = -1;

    CHECK(_update_dev_mapper_node(name));

done:

    if (hexkey)
        vic_free(hexkey);

    if (ctl >= 0)
        close(ctl);

    if (dmi)
        free(dmi);

    return result;
}
#endif /* !USE_LIBDEVMAPPER */

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

    return result;
}
