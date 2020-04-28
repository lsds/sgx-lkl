#ifndef _MUSLKL_VIRTIO_NET_H
#define _MUSLKL_VIRTIO_NET_H

struct ifreq;

/**
 * lkl_register_netdev_linux_fdnet - register a file descriptor-based network
 * device as a NIC
 *
 * @fd - a POSIX file descriptor number for input/output
 * @sync_io - 1 if I/O should be synchronous, i.e. threads should busy wait for
 * I/O to complete.
 * @returns a struct lkl_netdev_linux_fdnet entry for virtio-net
 */
struct lkl_netdev* sgxlkl_register_netdev_fd(int fd, int sync_io);

#endif
