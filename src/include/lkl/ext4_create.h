#ifndef _LKL_EXT4_H
#define _LKL_EXT4_H

// Creates an ext4 filesystem image on the given device.
int make_ext4_dev(
    const char* device_name,
    int block_size,
    unsigned long long num_blocks);

#endif