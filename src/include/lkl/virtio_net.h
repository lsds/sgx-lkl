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

