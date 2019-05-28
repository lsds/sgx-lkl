#ifndef WIREGUARD_UTIL_H
#define WIREGUARD_UTIL_H

#include <sys/socket.h>
#include <stdbool.h>
#include "wireguard.h"

bool wgu_parse_ip(wg_allowedip *allowedip, const char *value);
bool wgu_parse_allowedips(wg_peer *peer, wg_allowedip **last_allowedip, const char *value);
bool wgu_parse_endpoint(struct sockaddr *endpoint, const char *value);
void wgu_add_peer(wg_device *dev, wg_peer *new_peer, bool set_device);

#endif /* WIREGUARD_UTIL_H */
