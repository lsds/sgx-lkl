#ifndef __VIRTIO_NETDEV_H__
#define __VIRTIO_NETDEV_H__

#include <host/virtio_dev.h>
#include <host/virtio_types.h>
#include <pthread.h>
#include <shared/virtio_ring_buff.h>
#include <stdint.h>

#define ETH_ALEN 6
#define PIPE_BUF 4096

/* The feature bitmap for virtio net */
#define VIRTIO_NET_F_CSUM 0       /* Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM 1 /* Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_CTRL_GUEST_OFFLOADS                                 \
    2                                  /* Dynamic offload configuration. \
                                        */
#define VIRTIO_NET_F_MTU 3             /* Initial MTU advice */
#define VIRTIO_NET_F_MAC 5             /* Host has given MAC address. */
#define VIRTIO_NET_F_GUEST_TSO4 7      /* Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6 8      /* Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN 9       /* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO 10      /* Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4 11      /* Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6 12      /* Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN 13       /* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO 14       /* Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF 15      /* Host can merge receive buffers. */
#define VIRTIO_NET_F_STATUS 16         /* virtio_net_config.status available */
#define VIRTIO_NET_F_CTRL_VQ 17        /* Control channel available */
#define VIRTIO_NET_F_CTRL_RX 18        /* Control channel RX mode support */
#define VIRTIO_NET_F_CTRL_VLAN 19      /* Control channel VLAN filtering */
#define VIRTIO_NET_F_CTRL_RX_EXTRA 20  /* Extra RX mode control support */
#define VIRTIO_NET_F_GUEST_ANNOUNCE 21 /* Guest can announce device on the */

struct virtio_net_hdr_v1
{
#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1 /* Use csum_start, csum_offset */
#define VIRTIO_NET_HDR_F_DATA_VALID 2 /* Csum is valid */
    uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE 0   /* Not a GSO frame */
#define VIRTIO_NET_HDR_GSO_TCPV4 1  /* GSO frame, IPv4 TCP (TSO) */
#define VIRTIO_NET_HDR_GSO_UDP 3    /* GSO frame, IPv4 UDP (UFO) */
#define VIRTIO_NET_HDR_GSO_TCPV6 4  /* GSO frame, IPv6 TCP */
#define VIRTIO_NET_HDR_GSO_ECN 0x80 /* TCP has ECN set */
    uint8_t gso_type;
    __virtio16 hdr_len;     /* Ethernet + IP + tcp/udp hdrs */
    __virtio16 gso_size;    /* Bytes to append to hdr_len per frame */
    __virtio16 csum_start;  /* Position to start checksumming from */
    __virtio16 csum_offset; /* Offset after that to place checksum */
    __virtio16 num_buffers; /* Number of merged rx buffers */
};

struct virtio_net_config
{
    /* The config defining mac address (if VIRTIO_NET_F_MAC) */
    uint8_t mac[ETH_ALEN];
    /* See VIRTIO_NET_F_STATUS and VIRTIO_NET_S_* above */
    uint16_t status;
    /* Maximum number of each of transmit and receive queues;
     * see VIRTIO_NET_F_MQ and VIRTIO_NET_CTRL_MQ.
     * Legal values are between 1 and 0x8000
     */
    uint16_t max_virtqueue_pairs;
    /* Default maximum transmit unit advice */
    uint16_t mtu;
    /*
     * speed, in units of 1Mb. All values 0 to INT_MAX are legal.
     * Any other value stands for unknown.
     */
    uint32_t speed;
    /*
     * 0x00 - half duplex
     * 0x01 - full duplex
     * Any other value stands for unknown.
     */
    uint8_t duplex;
} __attribute__((packed));

#endif //__VIRTIO_NETDEV_H__
