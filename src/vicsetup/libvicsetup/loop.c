#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/loop.h>
#include <string.h>
#include <limits.h>

#include "loop.h"
#include "raise.h"
#include "strings.h"

static int _get_free_loop_device(char dev[PATH_MAX])
{
    int ret = -1;
    int index;
    struct stat st;
    int ctl = -1;

    if ((ctl = open("/dev/loop-control", O_RDONLY | O_CLOEXEC)) < 0)
        goto done;

    if ((index = ioctl(ctl, LOOP_CTL_GET_FREE)) < 0)
        goto done;

    snprintf(dev, PATH_MAX, "/dev/loop%u", index);

    if (stat(dev, &st) != 0 || !S_ISBLK(st.st_mode))
        goto done;

    ret = 0;

done:

    if (ctl >= 0)
        close(ctl);

    return ret;
}

int vic_loop_attach(
    const char* path,
    uint64_t offset,
    bool readonly,
    bool autoclear,
    char dev_out[PATH_MAX])
{
    int ret = -1;
    int fd = -1;
    int loop_fd = -1;
    char dev[PATH_MAX];

    if (!path || !dev_out)
        goto done;

    /* Open the file */
    {
        int flags = readonly ? O_RDONLY : O_RDWR;

        if ((fd = open(path, flags | O_EXCL)) < 0)
        {
            if ((errno == EROFS || errno == EACCES) && !readonly)
            {
                flags = O_RDONLY;
                readonly = true;
                fd = open(path, flags | O_EXCL);
            }
        }

        if (fd < 0)
            goto done;
    }

    /* Associate the file with the next free loop device */
    for (;;)
    {
        int flags = readonly ? O_RDONLY : O_RDWR;

        if (_get_free_loop_device(dev) != 0)
            goto done;

        if ((loop_fd = open(dev, flags)) < 0)
            goto done;

        if (ioctl(loop_fd, LOOP_SET_FD, fd) >= 0)
            break;

        if (errno != EBUSY)
            goto done;

        close(loop_fd);
        loop_fd = -1;
    }

    /* Set the status info for this loop device */
    {
        struct loop_info64 info = {0};
        const int n = LO_NAME_SIZE;

        if (snprintf((char*)info.lo_file_name, n, "%s", path) >= n)
            goto done;

        info.lo_offset = offset;

        if (autoclear)
            info.lo_flags |= LO_FLAGS_AUTOCLEAR;

        if (ioctl(loop_fd, LOOP_SET_STATUS64, &info) < 0)
        {
            ioctl(loop_fd, LOOP_CLR_FD, 0);
            goto done;
        }
    }

    /* Verify that LOOP_SET_STATUS64 was successful */
    {
        struct loop_info64 info = {0};

        if (ioctl(loop_fd, LOOP_GET_STATUS64, &info) < 0)
            goto done;

        if (autoclear && !(info.lo_flags & LO_FLAGS_AUTOCLEAR))
            goto done;

        if (info.lo_offset != offset)
            goto done;

        if (strcmp((const char*)info.lo_file_name, path) != 0)
            goto done;
    }

    strcpy(dev_out, dev);

    ret = 0;

done:

    if (fd >= 0)
        close(fd);

    if (loop_fd >= 0)
        close(loop_fd);

    return ret;
}

vic_result_t vic_loop_map(
    const char* path,
    char path_out[PATH_MAX],
    bool readonly)
{
    vic_result_t result = VIC_OK;
    struct stat st;

    if (!path || !path_out)
        RAISE(VIC_BAD_PARAMETER);

    if (stat(path, &st) != 0)
        RAISE(VIC_FAILED);

    if (S_ISBLK(st.st_mode))
    {
        if (vic_strlcpy(path_out, path, PATH_MAX) >= PATH_MAX)
            RAISE(VIC_PATH_TOO_LONG);
    }
    else
    {
        if (vic_loop_attach(path, 0, readonly, false, path_out) != 0)
            RAISE(VIC_FAILED_TO_GET_LOOP_DEVICE);
    }

done:
    return result;
}
