#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define _GNU_SOURCE
#include <net/if.h>
#include <string.h>
#include <unistd.h>

#include "sgx_enclave_config.h"
#include "sgxlkl_util.h"
#include "wireguard.h"

bool wgu_parse_ip(wg_allowedip *allowedip, const char *value) {
    allowedip->family = AF_UNSPEC;
    if (strchr(value, ':')) {
        if (inet_pton(AF_INET6, value, &allowedip->ip6) == 1)
            allowedip->family = AF_INET6;
    } else {
        if (inet_pton(AF_INET, value, &allowedip->ip4) == 1)
            allowedip->family = AF_INET;
    }
    if (allowedip->family == AF_UNSPEC) {
        fprintf(stderr, "Unable to parse IP address: `%s'\n", value);
        return false;
    }
    return true;
}

bool wgu_parse_allowedips(wg_peer *peer, wg_allowedip **last_allowedip, const char *value) {
    wg_allowedip *allowedip = *last_allowedip, *new_allowedip;
    char *mask, *mutable = strdup(value), *sep, *saved_entry;

    if (!mutable) {
        perror("strdup");
        return false;
    }
    peer->flags |= WGPEER_REPLACE_ALLOWEDIPS;
    if (!strlen(value)) {
        free(mutable);
        return true;
    }
    sep = mutable;
    while ((mask = strsep(&sep, ","))) {
        unsigned long cidr;
        char *end, *ip;

        saved_entry = strdup(mask);
        ip = strsep(&mask, "/");

        new_allowedip = calloc(1, sizeof(*new_allowedip));
        if (!new_allowedip) {
            perror("calloc");
            free(saved_entry);
            free(mutable);
            return false;
        }

        if (!wgu_parse_ip(new_allowedip, ip)) {
            free(new_allowedip);
            free(saved_entry);
            free(mutable);
            return false;
        }

        if (mask) {
            if (!isdigit(mask[0]))
                goto err;
            cidr = strtoul(mask, &end, 10);
            if (*end || (cidr > 32 && new_allowedip->family == AF_INET) || (cidr > 128 && new_allowedip->family == AF_INET6))
                goto err;
        } else if (new_allowedip->family == AF_INET)
            cidr = 32;
        else if (new_allowedip->family == AF_INET6)
            cidr = 128;
        else
            goto err;
        new_allowedip->cidr = cidr;

        if (allowedip)
            allowedip->next_allowedip = new_allowedip;
        else
            peer->first_allowedip = new_allowedip;
        allowedip = new_allowedip;
        free(saved_entry);
    }
    free(mutable);
    *last_allowedip = allowedip;
    return true;

err:
    free(new_allowedip);
    free(mutable);
    fprintf(stderr, "AllowedIP is not in the correct format: `%s'\n", saved_entry);
    free(saved_entry);
    return false;
}

bool wgu_parse_endpoint(struct sockaddr *endpoint, const char *value)
{
    char *mutable = strdup(value);
    char *begin, *end;
    int ret;
    struct addrinfo *resolved;
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };
    if (!mutable) {
        perror("strdup");
        return false;
    }
    if (!strlen(value)) {
        free(mutable);
        fprintf(stderr, "Unable to parse empty endpoint\n");
        return false;
    }
    if (mutable[0] == '[') {
        begin = &mutable[1];
        end = strchr(mutable, ']');
        if (!end) {
            free(mutable);
            fprintf(stderr, "Unable to find matching brace of endpoint: `%s'\n", value);
            return false;
        }
        *end++ = '\0';
        if (*end++ != ':' || !*end) {
            free(mutable);
            fprintf(stderr, "Unable to find port of endpoint: `%s'\n", value);
            return false;
        }
    } else {
        begin = mutable;
        end = strrchr(mutable, ':');
        if (!end || !*(end + 1)) {
            free(mutable);
            fprintf(stderr, "Unable to find port of endpoint: `%s'\n", value);
            return false;
        }
        *end++ = '\0';
    }

    for (unsigned int timeout = 1000000;;) {
        ret = getaddrinfo(begin, end, &hints, &resolved);
        if (!ret)
            break;
        timeout = timeout * 3 / 2;
        /* The set of return codes that are "permanent failures". All other possibilities are potentially transient.
         *
         * This is according to https://sourceware.org/glibc/wiki/NameResolver which states:
         *    "From the perspective of the application that calls getaddrinfo() it perhaps
         *     doesn't matter that much since EAI_FAIL, EAI_NONAME and EAI_NODATA are all
         *     permanent failure codes and the causes are all permanent failures in the
         *     sense that there is no point in retrying later."
         *
         * So this is what we do, except FreeBSD removed EAI_NODATA some time ago, so that's conditional.
         */
        if (ret == EAI_NONAME || ret == EAI_FAIL ||
            #ifdef EAI_NODATA
                ret == EAI_NODATA ||
            #endif
                timeout >= 90000000) {
            free(mutable);
            fprintf(stderr, "%s: `%s'\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value);
            return false;
        }
        fprintf(stderr, "%s: `%s'. Trying again in %.2f seconds...\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value, timeout / 1000000.0);
        usleep(timeout);
    }

    if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) ||
        (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6)))
        memcpy(endpoint, resolved->ai_addr, resolved->ai_addrlen);
    else {
        freeaddrinfo(resolved);
        free(mutable);
        fprintf(stderr, "Neither IPv4 nor IPv6 address found: `%s'\n", value);
        return false;
    }
    freeaddrinfo(resolved);
    free(mutable);
    return true;
}

int wgu_add_peer(wg_device *dev, wg_peer *new_peer, bool set_device) {
    int ret;
    if (!dev->first_peer)
        dev->first_peer = dev->last_peer = new_peer;
    else {
        dev->last_peer->next_peer = new_peer;
        dev->last_peer = new_peer;
    }

    if (set_device && ((ret = wg_set_device(dev)) < 0)) {
        perror("Unable to add peer to wireguard device");
        return ret;
    }

    return 0;
}

int wgu_add_peers(wg_device *dev, enclave_wg_peer_config_t *peers, size_t num_peers, bool set_device) {
    int ret;
    wg_peer *new_peers = malloc(sizeof(*new_peers) * num_peers);
    for (int i = 0; i < num_peers; i++) {
        enclave_wg_peer_config_t peer_cfg = peers[i];

        if (!peers[i].key || !strlen(peers[i].key)) {
            sgxlkl_warn("Unable to add wireguard peer due to missing key.\n");
            continue;
        }
        if (!peers[i].allowed_ips || !strlen(peers[i].allowed_ips)) {
            sgxlkl_warn("Unable to add wireguard peer due to missing allowed ips configuration.\n");
            continue;
        }
        /*if (!peers[i].endpoint || !strlen(peers[i].endpoint)) {
            sgxlkl_warn("Unable to add wireguard peer due to missing endpoint.\n");
            continue;
        }*/

        memset(&new_peers[i], 0, sizeof(new_peers[i]));
        new_peers[i].flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;

        if (ret = wg_key_from_base64(new_peers[i].public_key, peer_cfg.key)) {
            goto err;
        }

        wg_allowedip *pallowedip = NULL;
        if (!wgu_parse_allowedips(&new_peers[i], &pallowedip, peer_cfg.allowed_ips)) {
            ret = -EINVAL;
            goto err;
        }

	if (peers[i].endpoint && strlen(peers[i].endpoint) && !wgu_parse_endpoint(&new_peers[i].endpoint.addr, peer_cfg.endpoint)) {
            ret = -EINVAL;
            goto err;
        }
    }

    for (int i = 0; i < num_peers; i++) {
        if (ret = wgu_add_peer(dev, &new_peers[i], set_device))
            return ret;
    }

    return 0;

err:
    free(new_peers);
    return ret;
}

void wgu_list_devices(void) {
    char *device_names, *device_name;
    size_t len;

    device_names = wg_list_device_names();
    if (!device_names) {
        perror("Unable to get device names");
        exit(1);
    }
    wg_for_each_device_name(device_names, device_name, len) {
        wg_device *device;
        wg_peer *peer;
        wg_key_b64_string key;

        if (wg_get_device(&device, device_name) < 0) {
            perror("Unable to get device");
            continue;
        }
        wg_key_to_base64(key, device->public_key);
        sgxlkl_info("%s has public key %s\n", device_name, key);
        wg_for_each_peer(device, peer) {
            wg_key_to_base64(key, peer->public_key);
            sgxlkl_info(" - peer %s\n", key);
        }
        wg_free_device(device);
    }
    free(device_names);
}

