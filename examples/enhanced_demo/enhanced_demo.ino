/**
 * WireGuard ESP32 Enhanced Demo
 *
 * Demonstrates the enhanced WireGuard library features:
 * - Error handling with WireGuardError codes
 * - Connection state callbacks
 * - Pre-shared key (PSK) support
 * - Connection status monitoring
 * - NVS configuration storage
 * - Deep sleep support
 *
 * This example connects to a WireGuard server and periodically
 * sends UDP packets while monitoring connection status.
 */

#include <WiFi.h>
#include <WireGuard-ESP32.h>
#include <WireGuard-ESP32-NVS.h>

// ============== Configuration ==============
// WiFi credentials
const char* WIFI_SSID = "your_wifi_ssid";
const char* WIFI_PASSWORD = "your_wifi_password";

// WireGuard configuration
// Get these from your WireGuard server configuration
const char* WG_PRIVATE_KEY = "your_private_key_base64==";
const char* WG_PEER_PUBLIC_KEY = "peer_public_key_base64==";
const char* WG_PEER_ENDPOINT = "vpn.example.com";
const uint16_t WG_PEER_PORT = 51820;
const IPAddress WG_LOCAL_IP(10, 0, 0, 2);

// Optional: Pre-shared key for additional security
// Set to nullptr if not using PSK
const char* WG_PRESHARED_KEY = nullptr;  // "psk_base64==" if using PSK

// ============== Global Objects ==============
WireGuard wg;
WireGuardNVS wgNvs;

// Connection state tracking
volatile bool vpnConnected = false;
uint32_t lastStatusPrint = 0;
uint32_t connectionAttempts = 0;

// ============== Callbacks ==============
void onVpnStateChange(bool connected) {
    vpnConnected = connected;
    if (connected) {
        Serial.println("[VPN] Connected to peer!");
        Serial.printf("[VPN] Peer endpoint: %s:%d\n",
                      wg.getPeerEndpoint().toString().c_str(),
                      wg.getPeerPort());
    } else {
        Serial.println("[VPN] Disconnected from peer");
    }
}

// ============== Setup ==============
void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n========================================");
    Serial.println("WireGuard ESP32 Enhanced Demo");
    Serial.println("========================================\n");

    // Check if waking from deep sleep
    if (WireGuardDeepSleep::isWakingFromSleep()) {
        Serial.println("[Sleep] Waking from deep sleep");
        uint32_t delay_ms = WireGuardDeepSleep::getReconnectDelay();
        if (delay_ms > 0) {
            Serial.printf("[Sleep] Staggered reconnect delay: %u ms\n", delay_ms);
            delay(delay_ms);
        }
    }

    // Connect to WiFi
    connectWiFi();

    // Synchronize time via NTP (required for WireGuard handshakes)
    syncTime();

    // Initialize NVS storage
    if (wgNvs.begin()) {
        Serial.println("[NVS] Storage initialized");

        // Check if we have a saved configuration
        if (wgNvs.hasConfig()) {
            Serial.println("[NVS] Found saved configuration");
            // You could load from NVS here instead of using constants
        }
    }

    // Set up connection state callback
    wg.setStateCallback(onVpnStateChange);

    // Configure keepalive
    wg.setKeepaliveInterval(25);  // 25 seconds

    // Initialize WireGuard with error handling
    initializeWireGuard();
}

// ============== Main Loop ==============
void loop() {
    // Print status every 10 seconds
    if (millis() - lastStatusPrint >= 10000) {
        lastStatusPrint = millis();
        printStatus();
    }

    // Example: Send UDP packet if connected
    if (vpnConnected) {
        // Your application logic here
        // e.g., send sensor data over VPN
    }

    delay(100);
}

// ============== Helper Functions ==============
void connectWiFi() {
    Serial.printf("[WiFi] Connecting to %s", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    int attempts = 0;
    while (!WiFi.isConnected() && attempts < 30) {
        delay(500);
        Serial.print(".");
        attempts++;
    }

    if (WiFi.isConnected()) {
        Serial.println(" Connected!");
        Serial.printf("[WiFi] IP: %s\n", WiFi.localIP().toString().c_str());
    } else {
        Serial.println(" Failed!");
        Serial.println("[WiFi] Could not connect, restarting...");
        delay(3000);
        ESP.restart();
    }
}

void syncTime() {
    Serial.println("[NTP] Synchronizing time...");
    configTime(0, 0, "pool.ntp.org", "time.nist.gov", "time.google.com");

    // Wait for time sync (max 30 seconds)
    time_t now = 0;
    int attempts = 0;
    while (now < 1577836800 && attempts < 60) {  // Jan 1, 2020
        delay(500);
        time(&now);
        attempts++;
    }

    if (now >= 1577836800) {
        struct tm timeinfo;
        localtime_r(&now, &timeinfo);
        Serial.printf("[NTP] Time synchronized: %04d-%02d-%02d %02d:%02d:%02d\n",
                      timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                      timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    } else {
        Serial.println("[NTP] Warning: Time sync may have failed");
    }
}

void initializeWireGuard() {
    Serial.println("\n[WireGuard] Initializing...");
    Serial.printf("[WireGuard] Local IP: %s\n", WG_LOCAL_IP.toString().c_str());
    Serial.printf("[WireGuard] Endpoint: %s:%d\n", WG_PEER_ENDPOINT, WG_PEER_PORT);

    connectionAttempts++;

    // Initialize with new API that returns error codes
    WireGuardError err = wg.begin(
        WG_LOCAL_IP,
        WG_PRIVATE_KEY,
        WG_PEER_ENDPOINT,
        WG_PEER_PUBLIC_KEY,
        WG_PEER_PORT,
        WG_PRESHARED_KEY  // Can be nullptr
    );

    if (err == WireGuardError::OK) {
        Serial.println("[WireGuard] Initialized successfully!");
        Serial.println("[WireGuard] Waiting for handshake...");

        // Optionally save successful config to NVS
        // saveCurrentConfig();
    } else {
        Serial.printf("[WireGuard] Failed: %s\n", WireGuard::errorToString(err));
        handleError(err);
    }
}

void handleError(WireGuardError err) {
    switch (err) {
        case WireGuardError::DNS_FAILED:
            Serial.println("[WireGuard] DNS resolution failed - check endpoint address");
            break;

        case WireGuardError::INVALID_PRIVATE_KEY:
        case WireGuardError::INVALID_PUBLIC_KEY:
            Serial.println("[WireGuard] Invalid key - check base64 encoding (44 chars)");
            break;

        case WireGuardError::TIME_NOT_SYNCED:
            Serial.println("[WireGuard] Time not synced - ensure NTP is working");
            break;

        default:
            Serial.printf("[WireGuard] Error code: %d\n", (int)err);
    }

    // Retry after delay
    Serial.println("[WireGuard] Retrying in 10 seconds...");
    delay(10000);
    initializeWireGuard();
}

void printStatus() {
    Serial.println("\n--- Status ---");
    Serial.printf("WiFi: %s (RSSI: %d dBm)\n",
                  WiFi.isConnected() ? "Connected" : "Disconnected",
                  WiFi.RSSI());
    Serial.printf("VPN Initialized: %s\n", wg.is_initialized() ? "Yes" : "No");
    Serial.printf("VPN Connected: %s\n", wg.is_connected() ? "Yes" : "No");

    if (wg.is_connected()) {
        Serial.printf("Peer: %s:%d\n",
                      wg.getPeerEndpoint().toString().c_str(),
                      wg.getPeerPort());
        Serial.printf("TX: %llu bytes, RX: %llu bytes\n",
                      wg.getTxBytes(), wg.getRxBytes());
    }

    Serial.printf("Connection attempts: %u\n", connectionAttempts);
    Serial.printf("Free heap: %u bytes\n", ESP.getFreeHeap());
    Serial.println("--------------\n");
}

void saveCurrentConfig() {
    WireGuardConfig config;
    WireGuardNVS::createConfig(
        config,
        WG_LOCAL_IP,
        IPAddress(255, 255, 255, 255),
        IPAddress(0, 0, 0, 0),
        WG_PRIVATE_KEY,
        WG_PEER_PUBLIC_KEY,
        WG_PEER_ENDPOINT,
        WG_PEER_PORT,
        WG_PRESHARED_KEY,
        wg.getKeepaliveInterval()
    );

    if (wgNvs.saveConfig(config)) {
        Serial.println("[NVS] Configuration saved");
    }
}

// Example: Enter deep sleep for 5 minutes
void enterDeepSleep() {
    Serial.println("[Sleep] Preparing for deep sleep...");

    // Save state for faster reconnection
    WireGuardDeepSleep::prepareForSleep(wg);

    // Shutdown VPN cleanly
    wg.end();

    // Configure wake-up
    esp_sleep_enable_timer_wakeup(5 * 60 * 1000000ULL);  // 5 minutes

    Serial.println("[Sleep] Entering deep sleep...");
    delay(100);
    esp_deep_sleep_start();
}
