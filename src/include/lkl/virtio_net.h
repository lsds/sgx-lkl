/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#ifndef _MUSLKL_VIRTIO_NET_H
#define _MUSLKL_VIRTIO_NET_H

struct ifreq;

/**
 * lkl_register_netdev_linux_fdnet - register a file descriptor-based network
 * device as a NIC
 *
 * @fd - a POSIX file descriptor number for input/output
 * @returns a struct lkl_netdev_linux_fdnet entry for virtio-net
 */
struct lkl_netdev* sgxlkl_register_netdev_fd(int fd);

#endif

