/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * Enhanced by Claude - Added DDoS protection, time validation, ESP32 variant support
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "wireguard-platform.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "crypto.h"
#include "lwip/sys.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_system.h"
#include "esp_log.h"

// ESP-IDF version detection for API compatibility
#include "esp_idf_version.h"
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(4, 1, 0)
    #include "esp_sntp.h"
#else
    #include "lwip/apps/sntp.h"
#endif

static const char *TAG = "wireguard-platform";

// RNG context
static struct mbedtls_ctr_drbg_context random_context;
static struct mbedtls_entropy_context entropy_context;
static bool is_platform_initialized = false;

// DDoS protection state
static uint32_t packet_count = 0;
static uint32_t last_packet_count_reset = 0;

/**
 * Hardware entropy source callback for mbedTLS
 * Uses ESP32's hardware RNG which is cryptographically secure when WiFi/BT enabled
 */
static int entropy_hw_random_source(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;  // Unused parameter
    esp_fill_random(output, len);
    *olen = len;
    return 0;
}

/**
 * Initialize platform-specific resources
 * Sets up cryptographically secure RNG using hardware entropy
 */
void wireguard_platform_init() {
    if (is_platform_initialized) return;

    // Initialize mbedTLS entropy and DRBG
    mbedtls_entropy_init(&entropy_context);
    mbedtls_ctr_drbg_init(&random_context);

    // Add hardware RNG as entropy source
    // 134 bytes threshold, marked as strong source
    int ret = mbedtls_entropy_add_source(&entropy_context, entropy_hw_random_source,
                                          NULL, 134, MBEDTLS_ENTROPY_SOURCE_STRONG);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to add entropy source: %d", ret);
    }

    // Seed the DRBG
    ret = mbedtls_ctr_drbg_seed(&random_context, mbedtls_entropy_func,
                                 &entropy_context, NULL, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to seed DRBG: %d", ret);
    }

    // Initialize packet counter
    last_packet_count_reset = sys_now();
    packet_count = 0;

    is_platform_initialized = true;
    ESP_LOGI(TAG, "Platform initialized successfully");
}

/**
 * Generate cryptographically secure random bytes
 */
void wireguard_random_bytes(void *bytes, size_t size) {
    if (!is_platform_initialized) {
        ESP_LOGW(TAG, "Platform not initialized, initializing now");
        wireguard_platform_init();
    }
    mbedtls_ctr_drbg_random(&random_context, (unsigned char *)bytes, size);
}

/**
 * Get current system time in milliseconds
 */
uint32_t wireguard_sys_now() {
    return sys_now();
}

/**
 * Check if system time has been synchronized via NTP
 * Time must be after Jan 1, 2020 to be considered valid
 */
bool wireguard_time_is_valid() {
    time_t now;
    time(&now);
    return now > (time_t)WIREGUARD_MIN_VALID_TIMESTAMP;
}

/**
 * Generate TAI64N timestamp for handshake replay protection
 * See https://cr.yp.to/libtai/tai64.html
 *
 * Format:
 * - 8 bytes: seconds since epoch + 2^62 (TAI64 format)
 * - 4 bytes: nanoseconds within current second
 *
 * NOTE: System time MUST be synchronized via NTP before calling this function
 * Handshakes will fail if time is not synchronized
 */
void wireguard_tai64n_now(uint8_t *output) {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    // Warn if time appears invalid
    if (!wireguard_time_is_valid()) {
        ESP_LOGW(TAG, "System time may not be synchronized - handshake may fail");
    }

    // TAI64 = seconds + 2^62 offset
    // 0x400000000000000aULL includes the TAI-UTC offset (~37 seconds as of 2020)
    uint64_t seconds = 0x400000000000000aULL + (uint64_t)tv.tv_sec;

    // Convert microseconds to nanoseconds
    uint32_t nanos = (uint32_t)(tv.tv_usec * 1000);

    // Write in big-endian format
    U64TO8_BIG(output + 0, seconds);
    U32TO8_BIG(output + 8, nanos);
}

/**
 * Increment packet counter for DDoS load detection
 * Should be called for each incoming handshake initiation
 */
void wireguard_platform_count_packet() {
    uint32_t now = sys_now();

    // Reset counter every second
    if (now - last_packet_count_reset >= 1000) {
        packet_count = 0;
        last_packet_count_reset = now;
    }

    packet_count++;
}

/**
 * Check if system is under high load (potential DDoS)
 * When under load, WireGuard will require valid cookies for handshakes
 */
bool wireguard_is_under_load() {
    uint32_t now = sys_now();

    // Reset counter if more than 1 second has passed
    if (now - last_packet_count_reset >= 1000) {
        packet_count = 0;
        last_packet_count_reset = now;
        return false;
    }

    return packet_count > WIREGUARD_LOAD_THRESHOLD_PPS;
}
