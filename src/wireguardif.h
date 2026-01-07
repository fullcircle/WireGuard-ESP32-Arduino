/*
 * Ported to ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * Enhanced by Claude - Added PSK string support, fixed typos, improved docs
 * The original license is below:
 *
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Daniel Hope <daniel.hope@smartalock.com>
 */

#ifndef _WIREGUARDIF_H_
#define _WIREGUARDIF_H_

#include "lwip/arch.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"

// Default MTU for WireGuard is 1420 bytes
#define WIREGUARDIF_MTU (1420)

// Default WireGuard UDP port
#define WIREGUARDIF_DEFAULT_PORT        (51820)

// Special value indicating keepalive should use default (10 seconds)
#define WIREGUARDIF_KEEPALIVE_DEFAULT   (0xFFFF)

/**
 * WireGuard interface initialization data
 */
struct wireguardif_init_data {
    // Required: the private key of this WireGuard network interface (base64 encoded)
    const char *private_key;
    // Required: What UDP port to listen on
    u16_t listen_port;
    // Optional: restrict send/receive of encapsulated WireGuard traffic to this network interface only
    // Set to NULL to use routing table
    struct netif *bind_netif;
};

/**
 * WireGuard peer configuration
 */
struct wireguardif_peer {
    // Required: Peer's public key (base64 encoded, 44 characters)
    const char *public_key;

    // Optional: Pre-shared key for additional security (base64 encoded, 44 characters)
    // Set to NULL if not using PSK
    const char *preshared_key;

    // TAI64N of largest timestamp seen during handshake (for replay protection)
    // Usually initialized to zeros
    uint8_t greatest_timestamp[12];

    // Required: Allowed IP address for this peer
    ip_addr_t allowed_ip;
    // Required: Netmask for allowed IP (use 0.0.0.0 for all traffic)
    ip_addr_t allowed_mask;

    // Peer endpoint (required for initiating connections)
    ip_addr_t endpoint_ip;
    // Peer endpoint port (use WIREGUARDIF_DEFAULT_PORT for 51820)
    u16_t endpoint_port;

    // Keepalive interval in seconds (0 to disable, WIREGUARDIF_KEEPALIVE_DEFAULT for 10s)
    u16_t keep_alive;
};

// Backward compatibility for typo in original API
#define endport_port endpoint_port

// Invalid peer index (returned when peer allocation fails)
#define WIREGUARDIF_INVALID_INDEX (0xFF)

/*
 * Usage Example:
 * ==============
 *
 * static struct netif wg_netif_struct = {0};
 * struct wireguardif_init_data wg;
 * wg.private_key = "abcdefxxx..xxxxx=";  // Base64 private key
 * wg.listen_port = 51820;
 * wg.bind_netif = NULL;  // NULL for all interfaces
 *
 * netif = netif_add(&netif_struct, &ipaddr, &netmask, &gateway,
 *                   &wg, &wireguardif_init, &ip_input);
 * netif_set_up(wg_netif);
 *
 * struct wireguardif_peer peer;
 * wireguardif_peer_init(&peer);
 * peer.public_key = "apoehc...4322abcdfejg=";
 * peer.preshared_key = NULL;  // Or base64 PSK
 * peer.allowed_ip = allowed_ip;
 * peer.allowed_mask = allowed_mask;
 * peer.endpoint_ip = peer_ip;
 * peer.endpoint_port = 51820;
 *
 * uint8_t peer_index;
 * wireguardif_add_peer(netif, &peer, &peer_index);
 *
 * if (peer_index != WIREGUARDIF_INVALID_INDEX && !ip_addr_isany(&peer.endpoint_ip)) {
 *     wireguardif_connect(netif, peer_index);
 * }
 */

/**
 * Initialize a new WireGuard network interface
 *
 * @param netif Network interface to initialize (state should be wireguardif_init_data*)
 * @return ERR_OK on success
 */
err_t wireguardif_init(struct netif *netif);

/**
 * Shutdown a WireGuard network interface and release resources
 *
 * @param netif Network interface to shutdown
 */
void wireguardif_shutdown(struct netif *netif);

/**
 * Initialize peer structure with default values
 *
 * @param peer Peer structure to initialize
 */
void wireguardif_peer_init(struct wireguardif_peer *peer);

/**
 * Add a new peer to the WireGuard interface
 *
 * @param netif WireGuard network interface
 * @param peer Peer configuration
 * @param peer_index Output: index of added peer (use in other functions)
 * @return ERR_OK on success, ERR_MEM if no peer slots available
 */
err_t wireguardif_add_peer(struct netif *netif, struct wireguardif_peer *peer, u8_t *peer_index);

/**
 * Remove a peer from the WireGuard interface
 *
 * @param netif WireGuard network interface
 * @param peer_index Index of peer to remove
 * @return ERR_OK on success
 */
err_t wireguardif_remove_peer(struct netif *netif, u8_t peer_index);

/**
 * Update the endpoint address of a peer
 *
 * @param netif WireGuard network interface
 * @param peer_index Index of peer to update
 * @param ip New endpoint IP address
 * @param port New endpoint port
 * @return ERR_OK on success
 */
err_t wireguardif_update_endpoint(struct netif *netif, u8_t peer_index, const ip_addr_t *ip, u16_t port);

/**
 * Initiate connection to a peer
 * This starts the handshake process
 *
 * @param netif WireGuard network interface
 * @param peer_index Index of peer to connect to
 * @return ERR_OK on success
 */
err_t wireguardif_connect(struct netif *netif, u8_t peer_index);

/**
 * Disconnect from a peer
 * This destroys the session keys
 *
 * @param netif WireGuard network interface
 * @param peer_index Index of peer to disconnect
 * @return ERR_OK on success
 */
err_t wireguardif_disconnect(struct netif *netif, u8_t peer_index);

/**
 * Check if a peer connection is active
 * A peer is "up" if it has valid session keys
 *
 * @param netif WireGuard network interface
 * @param peer_index Index of peer to check
 * @param current_ip Output: current peer IP (can be NULL)
 * @param current_port Output: current peer port (can be NULL)
 * @return ERR_OK if connected, ERR_CONN if not connected
 */
err_t wireguardif_peer_is_up(struct netif *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port);

#endif /* _WIREGUARDIF_H_ */
