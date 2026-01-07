/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * Enhanced by Claude - Added PSK, callbacks, status methods, error handling
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#include <IPAddress.h>
#include <functional>

/**
 * WireGuard error codes for detailed error reporting
 */
enum class WireGuardError {
    OK = 0,                    // Success
    INVALID_PRIVATE_KEY,       // Private key is null or wrong length
    INVALID_PUBLIC_KEY,        // Public key is null or wrong length
    INVALID_ENDPOINT,          // Endpoint address is null or empty
    INVALID_PORT,              // Port is 0 or > 65535
    INVALID_PRESHARED_KEY,     // Pre-shared key is wrong length
    DNS_FAILED,                // Failed to resolve endpoint hostname
    NETWORK_INIT_FAILED,       // Failed to initialize network interface
    PEER_INIT_FAILED,          // Failed to initialize peer
    TIME_NOT_SYNCED,           // System time not synchronized via NTP
    ALREADY_INITIALIZED,       // WireGuard already initialized
    NOT_INITIALIZED,           // WireGuard not initialized
    MEMORY_ERROR               // Memory allocation failed
};

/**
 * Connection state callback type
 * @param connected True if peer is connected, false if disconnected
 */
using WireGuardStateCallback = std::function<void(bool connected)>;

/**
 * WireGuard VPN client for ESP32
 *
 * Provides a simple interface to establish WireGuard VPN tunnels on ESP32.
 *
 * Example usage:
 * @code
 * WireGuard wg;
 *
 * // Set up state callback (optional)
 * wg.setStateCallback([](bool connected) {
 *     Serial.println(connected ? "VPN Connected" : "VPN Disconnected");
 * });
 *
 * // Connect to WireGuard server
 * if (wg.begin(localIP, privateKey, endpoint, publicKey, port) == WireGuardError::OK) {
 *     Serial.println("WireGuard initialized");
 * }
 * @endcode
 *
 * @note System time MUST be synchronized via NTP before calling begin()
 */
class WireGuard
{
public:
    // ============== Constants ==============

    static constexpr size_t BASE64_KEY_LENGTH = 44;        // Base64-encoded 32-byte key
    static constexpr uint16_t DEFAULT_PORT = 51820;        // Default WireGuard port
    static constexpr uint16_t DEFAULT_KEEPALIVE = 25;      // Default keepalive in seconds
    static constexpr uint32_t DNS_TIMEOUT_MS = 30000;      // DNS resolution timeout
    static constexpr int DNS_MAX_RETRIES = 10;             // Maximum DNS retry attempts

    // ============== Constructors ==============

    WireGuard() = default;
    ~WireGuard();

    // Prevent copying (contains network resources)
    WireGuard(const WireGuard&) = delete;
    WireGuard& operator=(const WireGuard&) = delete;

    // ============== Initialization ==============

    /**
     * Initialize WireGuard VPN tunnel with full configuration
     *
     * @param localIP        Local IP address within the VPN tunnel
     * @param subnet         Subnet mask for VPN network (e.g., 255.255.255.0)
     * @param gateway        Gateway IP address (usually 0.0.0.0 for VPN)
     * @param privateKey     Base64-encoded WireGuard private key (44 chars)
     * @param remotePeerAddress Hostname or IP address of WireGuard server
     * @param remotePeerPublicKey Base64-encoded server public key (44 chars)
     * @param remotePeerPort Server WireGuard port (default 51820)
     * @param presharedKey   Optional pre-shared key for additional security (44 chars)
     *
     * @return WireGuardError::OK on success, error code on failure
     */
    WireGuardError begin(
        const IPAddress& localIP,
        const IPAddress& subnet,
        const IPAddress& gateway,
        const char* privateKey,
        const char* remotePeerAddress,
        const char* remotePeerPublicKey,
        uint16_t remotePeerPort = DEFAULT_PORT,
        const char* presharedKey = nullptr
    );

    /**
     * Initialize WireGuard VPN tunnel with simplified configuration
     * Uses default subnet (255.255.255.255) and gateway (0.0.0.0)
     *
     * @param localIP        Local IP address within the VPN tunnel
     * @param privateKey     Base64-encoded WireGuard private key
     * @param remotePeerAddress Hostname or IP of WireGuard server
     * @param remotePeerPublicKey Base64-encoded server public key
     * @param remotePeerPort Server WireGuard port (default 51820)
     * @param presharedKey   Optional pre-shared key (44 chars)
     *
     * @return WireGuardError::OK on success, error code on failure
     */
    WireGuardError begin(
        const IPAddress& localIP,
        const char* privateKey,
        const char* remotePeerAddress,
        const char* remotePeerPublicKey,
        uint16_t remotePeerPort = DEFAULT_PORT,
        const char* presharedKey = nullptr
    );

    /**
     * Legacy begin() for backward compatibility - returns bool
     */
    bool begin(
        const IPAddress& localIP,
        const IPAddress& subnet,
        const IPAddress& gateway,
        const char* privateKey,
        const char* remotePeerAddress,
        const char* remotePeerPublicKey,
        uint16_t remotePeerPort
    ) {
        return begin(localIP, subnet, gateway, privateKey, remotePeerAddress,
                     remotePeerPublicKey, remotePeerPort, nullptr) == WireGuardError::OK;
    }

    /**
     * Shutdown WireGuard tunnel and release resources
     */
    void end();

    // ============== Status Methods ==============

    /**
     * Check if WireGuard has been initialized
     * @return true if begin() was called successfully
     */
    bool is_initialized() const { return _is_initialized; }

    /**
     * Check if WireGuard peer is connected
     * Connection is established when handshake completes successfully
     * @return true if connected to peer
     */
    bool is_connected() const;

    /**
     * Get the last error that occurred
     * @return Last error code
     */
    WireGuardError getLastError() const { return _last_error; }

    /**
     * Get human-readable error description
     * @param error Error code to describe
     * @return Static string describing the error
     */
    static const char* errorToString(WireGuardError error);

    // ============== Statistics ==============

    /**
     * Get number of bytes transmitted through tunnel
     * @return Total bytes sent
     */
    uint64_t getTxBytes() const;

    /**
     * Get number of bytes received through tunnel
     * @return Total bytes received
     */
    uint64_t getRxBytes() const;

    /**
     * Get time of last successful handshake
     * @return Milliseconds since boot of last handshake, 0 if never connected
     */
    uint32_t getLastHandshakeTime() const;

    /**
     * Get current peer endpoint IP address
     * @return IP address of connected peer
     */
    IPAddress getPeerEndpoint() const;

    /**
     * Get current peer endpoint port
     * @return Port number of connected peer
     */
    uint16_t getPeerPort() const;

    // ============== Configuration ==============

    /**
     * Set keepalive interval
     * Sends empty packets to maintain NAT mappings
     *
     * @param seconds Interval in seconds (0 to disable, default 25)
     */
    void setKeepaliveInterval(uint16_t seconds);

    /**
     * Get current keepalive interval
     * @return Keepalive interval in seconds
     */
    uint16_t getKeepaliveInterval() const { return _keepalive_seconds; }

    /**
     * Set connection state change callback
     * Called when peer connection state changes
     *
     * @param callback Function to call on state change
     */
    void setStateCallback(WireGuardStateCallback callback) {
        _state_callback = callback;
    }

private:
    bool _is_initialized = false;
    WireGuardError _last_error = WireGuardError::OK;
    uint16_t _keepalive_seconds = DEFAULT_KEEPALIVE;
    WireGuardStateCallback _state_callback = nullptr;

    // Internal state tracking
    bool _was_connected = false;

    // Check and invoke state callback if connection state changed
    void checkStateCallback();
};
