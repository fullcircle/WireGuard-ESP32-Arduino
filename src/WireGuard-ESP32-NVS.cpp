/*
 * WireGuard NVS Storage Support for ESP32
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "WireGuard-ESP32-NVS.h"

#include <nvs_flash.h>
#include <nvs.h>
#include <cstring>
#include "esp_system.h"
#include "esp_sleep.h"
#include "esp32-hal-log.h"

static const char* TAG = "[WireGuard-NVS]";

// RTC memory for deep sleep state (survives deep sleep)
RTC_DATA_ATTR static uint32_t rtc_magic = 0;
RTC_DATA_ATTR static uint32_t rtc_wake_count = 0;
RTC_DATA_ATTR static uint32_t rtc_last_handshake = 0;

static const uint32_t RTC_MAGIC_VALUE = 0x57475253;  // "WGRS"

// ============== WireGuardNVS Implementation ==============

bool WireGuardNVS::begin(const char* namespace_name) {
    if (_initialized) return true;

    // Initialize NVS if not already done
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition was truncated, erase and retry
        log_w("%s NVS needs erase, erasing...", TAG);
        nvs_flash_erase();
        err = nvs_flash_init();
    }

    if (err != ESP_OK) {
        log_e("%s NVS init failed: %d", TAG, err);
        return false;
    }

    // Store namespace name
    strncpy(_namespace, namespace_name, sizeof(_namespace) - 1);
    _namespace[sizeof(_namespace) - 1] = '\0';

    _initialized = true;
    log_i("%s Initialized with namespace '%s'", TAG, _namespace);
    return true;
}

uint8_t WireGuardNVS::calculateChecksum(const WireGuardConfig& config) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(&config);
    uint8_t sum = 0;
    // Checksum all bytes except the checksum field itself
    for (size_t i = 0; i < offsetof(WireGuardConfig, checksum); i++) {
        sum ^= data[i];
        sum = (sum << 1) | (sum >> 7);  // Rotate left
    }
    return sum;
}

bool WireGuardNVS::saveConfig(const WireGuardConfig& config, const char* name) {
    if (!_initialized) {
        log_e("%s Not initialized", TAG);
        return false;
    }

    // Calculate checksum
    WireGuardConfig configCopy = config;
    configCopy.checksum = calculateChecksum(configCopy);

    nvs_handle_t handle;
    esp_err_t err = nvs_open(_namespace, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        log_e("%s Failed to open NVS: %d", TAG, err);
        return false;
    }

    err = nvs_set_blob(handle, name, &configCopy, sizeof(WireGuardConfig));
    if (err != ESP_OK) {
        log_e("%s Failed to write config: %d", TAG, err);
        nvs_close(handle);
        return false;
    }

    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        log_e("%s Failed to commit: %d", TAG, err);
        return false;
    }

    log_i("%s Config '%s' saved successfully", TAG, name);
    return true;
}

bool WireGuardNVS::loadConfig(WireGuardConfig& config, const char* name) {
    if (!_initialized) {
        log_e("%s Not initialized", TAG);
        return false;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(_namespace, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        log_e("%s Failed to open NVS: %d", TAG, err);
        return false;
    }

    size_t size = sizeof(WireGuardConfig);
    err = nvs_get_blob(handle, name, &config, &size);
    nvs_close(handle);

    if (err != ESP_OK) {
        log_e("%s Failed to read config '%s': %d", TAG, name, err);
        return false;
    }

    if (size != sizeof(WireGuardConfig)) {
        log_e("%s Config size mismatch", TAG);
        return false;
    }

    // Verify checksum
    uint8_t expected = calculateChecksum(config);
    if (config.checksum != expected) {
        log_e("%s Config checksum invalid", TAG);
        return false;
    }

    log_i("%s Config '%s' loaded successfully", TAG, name);
    return true;
}

bool WireGuardNVS::hasConfig(const char* name) {
    if (!_initialized) return false;

    nvs_handle_t handle;
    esp_err_t err = nvs_open(_namespace, NVS_READONLY, &handle);
    if (err != ESP_OK) return false;

    size_t size = 0;
    err = nvs_get_blob(handle, name, nullptr, &size);
    nvs_close(handle);

    return (err == ESP_OK && size == sizeof(WireGuardConfig));
}

bool WireGuardNVS::deleteConfig(const char* name) {
    if (!_initialized) return false;

    nvs_handle_t handle;
    esp_err_t err = nvs_open(_namespace, NVS_READWRITE, &handle);
    if (err != ESP_OK) return false;

    err = nvs_erase_key(handle, name);
    if (err == ESP_OK) {
        nvs_commit(handle);
    }
    nvs_close(handle);

    return err == ESP_OK;
}

WireGuardError WireGuardNVS::applyConfig(WireGuard& wg, const WireGuardConfig& config) {
    IPAddress localIP(config.localIP);
    IPAddress subnet(config.subnet);
    IPAddress gateway(config.gateway);

    const char* psk = (config.presharedKey[0] != '\0') ? config.presharedKey : nullptr;

    wg.setKeepaliveInterval(config.keepaliveSeconds);

    return wg.begin(
        localIP,
        subnet,
        gateway,
        config.privateKey,
        config.endpoint,
        config.peerPublicKey,
        config.endpointPort,
        psk
    );
}

void WireGuardNVS::createConfig(
    WireGuardConfig& config,
    const IPAddress& localIP,
    const IPAddress& subnet,
    const IPAddress& gateway,
    const char* privateKey,
    const char* peerPublicKey,
    const char* endpoint,
    uint16_t endpointPort,
    const char* presharedKey,
    uint16_t keepaliveSeconds
) {
    memset(&config, 0, sizeof(config));

    strncpy(config.privateKey, privateKey, sizeof(config.privateKey) - 1);
    strncpy(config.peerPublicKey, peerPublicKey, sizeof(config.peerPublicKey) - 1);
    strncpy(config.endpoint, endpoint, sizeof(config.endpoint) - 1);

    if (presharedKey != nullptr) {
        strncpy(config.presharedKey, presharedKey, sizeof(config.presharedKey) - 1);
    }

    config.endpointPort = endpointPort;
    config.localIP = static_cast<uint32_t>(localIP);
    config.subnet = static_cast<uint32_t>(subnet);
    config.gateway = static_cast<uint32_t>(gateway);
    config.keepaliveSeconds = keepaliveSeconds;
}

// ============== WireGuardDeepSleep Implementation ==============

void WireGuardDeepSleep::prepareForSleep(const WireGuard& wg) {
    rtc_magic = RTC_MAGIC_VALUE;
    rtc_wake_count++;
    rtc_last_handshake = wg.getLastHandshakeTime();
    log_i("%s Deep sleep prepared, wake count: %u", TAG, rtc_wake_count);
}

bool WireGuardDeepSleep::isWakingFromSleep() {
    if (rtc_magic != RTC_MAGIC_VALUE) {
        return false;
    }

    esp_sleep_wakeup_cause_t cause = esp_sleep_get_wakeup_cause();
    return cause != ESP_SLEEP_WAKEUP_UNDEFINED;
}

uint32_t WireGuardDeepSleep::getReconnectDelay() {
    if (!isWakingFromSleep()) {
        return 0;
    }

    // Use chip ID to create a pseudo-random but consistent delay per device
    // This helps prevent thundering herd when multiple devices wake simultaneously
    uint32_t chip_id = 0;
    for (int i = 0; i < 6; i++) {
        chip_id |= ((uint32_t)ESP.getEfuseMac() >> (i * 8)) & 0xFF;
    }

    // Delay between 0-2000ms based on chip ID
    return (chip_id % 2000);
}

void WireGuardDeepSleep::clearState() {
    rtc_magic = 0;
    log_i("%s Deep sleep state cleared", TAG);
}
