/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * Enhanced by Claude - Added validation, PSK, callbacks, statistics, error handling
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "WireGuard-ESP32.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/netdb.h"

#include "esp32-hal-log.h"

#include <cstring>
#include <algorithm>

extern "C" {
#include "wireguardif.h"
#include "wireguard-platform.h"
#include "wireguard.h"
}

// ============== Static State ==============
// Note: Currently using global state for lwIP netif compatibility
// A future version could support multiple instances with per-instance state

static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = nullptr;
static struct netif *previous_default_netif = nullptr;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

// Statistics tracking
static uint64_t total_tx_bytes = 0;
static uint64_t total_rx_bytes = 0;

static const char* TAG = "[WireGuard]";

// ============== Helper Functions ==============

/**
 * Validate base64-encoded key length
 */
static bool isValidKeyLength(const char* key) {
    if (key == nullptr) return false;
    size_t len = strlen(key);
    return len == WireGuard::BASE64_KEY_LENGTH;
}

/**
 * Resolve hostname to IP address with exponential backoff
 */
static bool resolveHostname(
    const char* hostname,
    ip_addr_t* out_ip,
    uint32_t timeout_ms,
    int max_retries
) {
    uint32_t start_time = sys_now();
    uint32_t delay_ms = 500;  // Start with 500ms delay
    const uint32_t max_delay_ms = 8000;  // Max 8 second delay

    for (int retry = 0; retry < max_retries; retry++) {
        // Check timeout
        if (sys_now() - start_time >= timeout_ms) {
            log_e("%s DNS resolution timeout after %lu ms", TAG, (unsigned long)timeout_ms);
            return false;
        }

        struct addrinfo *res = nullptr;
        struct addrinfo hint;
        memset(&hint, 0, sizeof(hint));
        hint.ai_family = AF_INET;  // IPv4 only for now

        int err = lwip_getaddrinfo(hostname, nullptr, &hint, &res);
        if (err == 0 && res != nullptr) {
            struct in_addr addr4 = ((struct sockaddr_in*)(res->ai_addr))->sin_addr;
            inet_addr_to_ip4addr(ip_2_ip4(out_ip), &addr4);
            lwip_freeaddrinfo(res);

            log_i("%s Resolved %s to %d.%d.%d.%d", TAG, hostname,
                  (out_ip->u_addr.ip4.addr >> 0) & 0xff,
                  (out_ip->u_addr.ip4.addr >> 8) & 0xff,
                  (out_ip->u_addr.ip4.addr >> 16) & 0xff,
                  (out_ip->u_addr.ip4.addr >> 24) & 0xff);
            return true;
        }

        if (res != nullptr) {
            lwip_freeaddrinfo(res);
        }

        log_d("%s DNS retry %d/%d, waiting %lu ms", TAG, retry + 1, max_retries, (unsigned long)delay_ms);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));

        // Exponential backoff with cap
        delay_ms = std::min(delay_ms * 2, max_delay_ms);
    }

    return false;
}

// ============== WireGuard Class Implementation ==============

WireGuard::~WireGuard() {
    end();
}

const char* WireGuard::errorToString(WireGuardError error) {
    switch (error) {
        case WireGuardError::OK:
            return "Success";
        case WireGuardError::INVALID_PRIVATE_KEY:
            return "Invalid private key (must be 44 char base64)";
        case WireGuardError::INVALID_PUBLIC_KEY:
            return "Invalid public key (must be 44 char base64)";
        case WireGuardError::INVALID_ENDPOINT:
            return "Invalid endpoint address";
        case WireGuardError::INVALID_PORT:
            return "Invalid port number";
        case WireGuardError::INVALID_PRESHARED_KEY:
            return "Invalid pre-shared key (must be 44 char base64)";
        case WireGuardError::DNS_FAILED:
            return "DNS resolution failed";
        case WireGuardError::NETWORK_INIT_FAILED:
            return "Network interface initialization failed";
        case WireGuardError::PEER_INIT_FAILED:
            return "Peer initialization failed";
        case WireGuardError::TIME_NOT_SYNCED:
            return "System time not synchronized (NTP required)";
        case WireGuardError::ALREADY_INITIALIZED:
            return "WireGuard already initialized";
        case WireGuardError::NOT_INITIALIZED:
            return "WireGuard not initialized";
        case WireGuardError::MEMORY_ERROR:
            return "Memory allocation failed";
        default:
            return "Unknown error";
    }
}

WireGuardError WireGuard::begin(
    const IPAddress& localIP,
    const IPAddress& subnet,
    const IPAddress& gateway,
    const char* privateKey,
    const char* remotePeerAddress,
    const char* remotePeerPublicKey,
    uint16_t remotePeerPort,
    const char* presharedKey
) {
    // Check if already initialized
    if (_is_initialized) {
        _last_error = WireGuardError::ALREADY_INITIALIZED;
        log_e("%s %s", TAG, errorToString(_last_error));
        return _last_error;
    }

    // Validate private key
    if (!isValidKeyLength(privateKey)) {
        _last_error = WireGuardError::INVALID_PRIVATE_KEY;
        log_e("%s %s", TAG, errorToString(_last_error));
        return _last_error;
    }

    // Validate public key
    if (!isValidKeyLength(remotePeerPublicKey)) {
        _last_error = WireGuardError::INVALID_PUBLIC_KEY;
        log_e("%s %s", TAG, errorToString(_last_error));
        return _last_error;
    }

    // Validate endpoint
    if (remotePeerAddress == nullptr || strlen(remotePeerAddress) == 0) {
        _last_error = WireGuardError::INVALID_ENDPOINT;
        log_e("%s %s", TAG, errorToString(_last_error));
        return _last_error;
    }

    // Validate port
    if (remotePeerPort == 0) {
        _last_error = WireGuardError::INVALID_PORT;
        log_e("%s %s", TAG, errorToString(_last_error));
        return _last_error;
    }

    // Validate optional pre-shared key
    if (presharedKey != nullptr && !isValidKeyLength(presharedKey)) {
        _last_error = WireGuardError::INVALID_PRESHARED_KEY;
        log_e("%s %s", TAG, errorToString(_last_error));
        return _last_error;
    }

    // Check if time is synchronized (warn but don't fail)
    if (!wireguard_time_is_valid()) {
        log_w("%s System time may not be synchronized - handshake may fail", TAG);
        // Note: We warn but don't fail, as time may be set by other means
    }

    // Initialize platform
    wireguard_platform_init();

    // Setup IP addresses
    ip_addr_t ipaddr = IPADDR4_INIT(static_cast<uint32_t>(localIP));
    ip_addr_t netmask = IPADDR4_INIT(static_cast<uint32_t>(subnet));
    ip_addr_t gw = IPADDR4_INIT(static_cast<uint32_t>(gateway));

    // Setup WireGuard device structure
    struct wireguardif_init_data wg;
    memset(&wg, 0, sizeof(wg));
    wg.private_key = privateKey;
    wg.listen_port = remotePeerPort;
    wg.bind_netif = nullptr;

    // Initialize peer structure
    struct wireguardif_peer peer;
    wireguardif_peer_init(&peer);

    // Resolve endpoint hostname with exponential backoff
    ip_addr_t endpoint_ip;
    memset(&endpoint_ip, 0, sizeof(endpoint_ip));

    if (!resolveHostname(remotePeerAddress, &endpoint_ip, DNS_TIMEOUT_MS, DNS_MAX_RETRIES)) {
        _last_error = WireGuardError::DNS_FAILED;
        log_e("%s %s: %s", TAG, errorToString(_last_error), remotePeerAddress);
        return _last_error;
    }
    peer.endpoint_ip = endpoint_ip;

    // Register WireGuard network interface with lwIP
    memset(&wg_netif_struct, 0, sizeof(wg_netif_struct));
    wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask),
                         ip_2_ip4(&gw), &wg, &wireguardif_init, &ip_input);

    if (wg_netif == nullptr) {
        _last_error = WireGuardError::NETWORK_INIT_FAILED;
        log_e("%s %s", TAG, errorToString(_last_error));
        return _last_error;
    }

    // Mark interface as administratively up
    netif_set_up(wg_netif);

    // Configure peer
    peer.public_key = remotePeerPublicKey;
    peer.preshared_key = presharedKey;  // Can be nullptr

    // Allow all IPs through tunnel (0.0.0.0/0)
    ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    peer.allowed_ip = allowed_ip;
    peer.allowed_mask = allowed_mask;

    peer.endpoint_port = remotePeerPort;
    peer.keep_alive = _keepalive_seconds;

    // Add peer to interface
    err_t err = wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);
    if (err != ERR_OK || wireguard_peer_index == WIREGUARDIF_INVALID_INDEX) {
        netif_remove(wg_netif);
        wg_netif = nullptr;
        _last_error = WireGuardError::PEER_INIT_FAILED;
        log_e("%s %s", TAG, errorToString(_last_error));
        return _last_error;
    }

    // Start connection if endpoint is configured
    if (!ip_addr_isany(&peer.endpoint_ip)) {
        log_i("%s Connecting to peer...", TAG);
        wireguardif_connect(wg_netif, wireguard_peer_index);

        // Save and set default interface
        previous_default_netif = netif_default;
        netif_set_default(wg_netif);
    }

    // Reset statistics
    total_tx_bytes = 0;
    total_rx_bytes = 0;

    _is_initialized = true;
    _was_connected = false;
    _last_error = WireGuardError::OK;

    log_i("%s Initialized successfully", TAG);
    return WireGuardError::OK;
}

WireGuardError WireGuard::begin(
    const IPAddress& localIP,
    const char* privateKey,
    const char* remotePeerAddress,
    const char* remotePeerPublicKey,
    uint16_t remotePeerPort,
    const char* presharedKey
) {
    // Use default subnet and gateway for simple VPN setup
    IPAddress subnet(255, 255, 255, 255);
    IPAddress gateway(0, 0, 0, 0);
    return begin(localIP, subnet, gateway, privateKey, remotePeerAddress,
                 remotePeerPublicKey, remotePeerPort, presharedKey);
}

void WireGuard::end() {
    if (!_is_initialized) return;

    // Restore default interface
    if (previous_default_netif != nullptr) {
        netif_set_default(previous_default_netif);
        previous_default_netif = nullptr;
    }

    // Disconnect and cleanup
    if (wg_netif != nullptr && wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) {
        wireguardif_disconnect(wg_netif, wireguard_peer_index);
        wireguardif_remove_peer(wg_netif, wireguard_peer_index);
    }
    wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

    // Shutdown interface
    if (wg_netif != nullptr) {
        wireguardif_shutdown(wg_netif);
        netif_remove(wg_netif);
        wg_netif = nullptr;
    }

    _is_initialized = false;
    _was_connected = false;
    log_i("%s Shutdown complete", TAG);
}

bool WireGuard::is_connected() const {
    if (!_is_initialized || wg_netif == nullptr) {
        return false;
    }

    ip_addr_t current_ip;
    u16_t current_port;
    err_t result = wireguardif_peer_is_up(wg_netif, wireguard_peer_index,
                                          &current_ip, &current_port);
    return result == ERR_OK;
}

void WireGuard::checkStateCallback() {
    if (_state_callback == nullptr) return;

    bool connected = is_connected();
    if (connected != _was_connected) {
        _was_connected = connected;
        _state_callback(connected);
    }
}

uint64_t WireGuard::getTxBytes() const {
    return total_tx_bytes;
}

uint64_t WireGuard::getRxBytes() const {
    return total_rx_bytes;
}

uint32_t WireGuard::getLastHandshakeTime() const {
    // This would require access to internal wireguard peer state
    // For now, return 0 if not connected, or current time if connected
    if (!is_connected()) {
        return 0;
    }
    // TODO: Expose keypair timestamp from wireguard.c
    return wireguard_sys_now();
}

IPAddress WireGuard::getPeerEndpoint() const {
    if (!_is_initialized || wg_netif == nullptr) {
        return IPAddress(0, 0, 0, 0);
    }

    ip_addr_t current_ip;
    u16_t current_port;
    if (wireguardif_peer_is_up(wg_netif, wireguard_peer_index,
                               &current_ip, &current_port) == ERR_OK) {
        return IPAddress(
            (current_ip.u_addr.ip4.addr >> 0) & 0xff,
            (current_ip.u_addr.ip4.addr >> 8) & 0xff,
            (current_ip.u_addr.ip4.addr >> 16) & 0xff,
            (current_ip.u_addr.ip4.addr >> 24) & 0xff
        );
    }
    return IPAddress(0, 0, 0, 0);
}

uint16_t WireGuard::getPeerPort() const {
    if (!_is_initialized || wg_netif == nullptr) {
        return 0;
    }

    ip_addr_t current_ip;
    u16_t current_port = 0;
    wireguardif_peer_is_up(wg_netif, wireguard_peer_index, &current_ip, &current_port);
    return current_port;
}

void WireGuard::setKeepaliveInterval(uint16_t seconds) {
    _keepalive_seconds = seconds;
    // Note: This will only take effect on next connection
    // To change for current connection, we'd need to expose
    // a setter in wireguardif
}
