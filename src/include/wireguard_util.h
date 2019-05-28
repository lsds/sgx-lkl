#ifndef WIREGUARD_UTIL_H
#define WIREGUARD_UTIL_H

#include <sys/socket.h>
#include <stdbool.h>
#include "sgx_enclave_config.h"
#include "wireguard.h"

bool wgu_parse_ip(wg_allowedip *allowedip, const char *value);
bool wgu_parse_allowedips(wg_peer *peer, wg_allowedip **last_allowedip, const char *value);
bool wgu_parse_endpoint(struct sockaddr *endpoint, const char *value);
int wgu_add_peers(wg_device *dev, enclave_wg_peer_config_t *peers, size_t num_peers, bool set_device);
int wgu_add_peer(wg_device *dev, wg_peer *new_peer, bool set_device);
void wgu_list_devices(void);

#endif /* WIREGUARD_UTIL_H */
