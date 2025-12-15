/*
 * WireGuard NVS Storage Support for ESP32
 * Enables persistent configuration storage and deep sleep resume
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#include "WireGuard-ESP32.h"
#include <IPAddress.h>

/**
 * WireGuard configuration structure for NVS storage
 */
struct WireGuardConfig {
    char privateKey[45];           // Base64 private key (44 chars + null)
    char peerPublicKey[45];        // Base64 peer public key
    char presharedKey[45];         // Base64 pre-shared key (optional, empty if not used)
    char endpoint[64];             // Peer endpoint hostname/IP
    uint16_t endpointPort;         // Peer endpoint port
    uint32_t localIP;              // Local VPN IP (as uint32)
    uint32_t subnet;               // Subnet mask
    uint32_t gateway;              // Gateway IP
    uint16_t keepaliveSeconds;     // Keepalive interval
    uint8_t checksum;              // Simple checksum for validation
};

/**
 * WireGuard NVS Storage Helper
 *
 * Provides persistent storage of WireGuard configuration in ESP32's
 * Non-Volatile Storage (NVS), enabling:
 * - Configuration persistence across reboots
 * - Quick reconnection after deep sleep
 * - Factory provisioning of VPN credentials
 *
 * Example usage:
 * @code
 * WireGuardNVS wgNvs;
 *
 * // Save configuration
 * WireGuardConfig config;
 * strcpy(config.privateKey, "...");
 * strcpy(config.peerPublicKey, "...");
 * // ...fill other fields...
 * wgNvs.saveConfig(config);
 *
 * // Load and connect
 * WireGuard wg;
 * if (wgNvs.loadConfig(config)) {
 *     wgNvs.applyConfig(wg, config);
 * }
 * @endcode
 */
class WireGuardNVS {
public:
    /**
     * Initialize NVS storage
     * @param namespace_name NVS namespace for WireGuard configs (default: "wireguard")
     * @return true if NVS initialized successfully
     */
    bool begin(const char* namespace_name = "wireguard");

    /**
     * Save WireGuard configuration to NVS
     * @param config Configuration to save
     * @param name Config name for multiple profiles (default: "default")
     * @return true on success
     */
    bool saveConfig(const WireGuardConfig& config, const char* name = "default");

    /**
     * Load WireGuard configuration from NVS
     * @param config Output configuration
     * @param name Config name to load (default: "default")
     * @return true if config loaded and valid
     */
    bool loadConfig(WireGuardConfig& config, const char* name = "default");

    /**
     * Check if a configuration exists in NVS
     * @param name Config name to check
     * @return true if config exists
     */
    bool hasConfig(const char* name = "default");

    /**
     * Delete a configuration from NVS
     * @param name Config name to delete
     * @return true on success
     */
    bool deleteConfig(const char* name = "default");

    /**
     * Apply loaded configuration to a WireGuard instance
     * @param wg WireGuard instance to configure
     * @param config Configuration to apply
     * @return WireGuardError result
     */
    static WireGuardError applyConfig(WireGuard& wg, const WireGuardConfig& config);

    /**
     * Create configuration from current WireGuard parameters
     * Helper for saving active configuration
     */
    static void createConfig(
        WireGuardConfig& config,
        const IPAddress& localIP,
        const IPAddress& subnet,
        const IPAddress& gateway,
        const char* privateKey,
        const char* peerPublicKey,
        const char* endpoint,
        uint16_t endpointPort,
        const char* presharedKey = nullptr,
        uint16_t keepaliveSeconds = 25
    );

private:
    bool _initialized = false;
    char _namespace[16];

    static uint8_t calculateChecksum(const WireGuardConfig& config);
};

/**
 * Deep Sleep Helper for WireGuard
 *
 * Stores minimal state in RTC memory to enable faster reconnection
 * after waking from deep sleep.
 *
 * Note: Full session keys cannot be preserved across deep sleep due to
 * security implications. This helper stores configuration and connection
 * metadata to speed up reconnection.
 */
class WireGuardDeepSleep {
public:
    /**
     * Prepare for deep sleep
     * Saves reconnection hints to RTC memory
     * @param wg Current WireGuard instance
     */
    static void prepareForSleep(const WireGuard& wg);

    /**
     * Check if waking from WireGuard-prepared deep sleep
     * @return true if RTC state is valid
     */
    static bool isWakingFromSleep();

    /**
     * Get recommended initial delay before reconnection
     * Helps avoid thundering herd if multiple devices wake simultaneously
     * @return Delay in milliseconds
     */
    static uint32_t getReconnectDelay();

    /**
     * Clear deep sleep state
     * Call after successful reconnection
     */
    static void clearState();
};
