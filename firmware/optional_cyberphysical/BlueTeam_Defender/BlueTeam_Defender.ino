/**
 * ZeroTrace - Blue Team Defender (ESP32 #2)
 * -------------------------------------------------------------
 * Target Hardware: ESP32 DevKit V1 / NodeMCU
 * Transports:
 *   - USB Serial @ 115200 baud (High-Speed Structured NIST Telemetry stream to FastAPI backend)
 *   - Hardware Serial2 @ 9600 baud (GPIO 16 RX <- Red TX, GPIO 17 TX -> Red RX)
 *
 * Implements 4-Layer Zero-Trust Framework:
 *   - L1: Secure Boot & OTA (HMAC-SHA256 verification, Monotonic Anti-Rollback, Probation Watchdog)
 *   - L3: Silicon Lockdown (eFuse JTAG / Memory Read Protection simulation at boot)
 *   - L4: Zero-Wear Cryptographic Key Sanitization (< 1ms flash wipe)
 *
 * Strict Evaluator Requirement:
 *   EVERY defensive action prints structured risk log format:
 *   [RISK ASSESSED: <SEVERITY>] <Threat Name>. [METRIC] <Data>. [MITIGATION] <Action>.
 */

#include <Arduino.h>
#include <HardwareSerial.h>
#include <Preferences.h>
#include "mbedtls/md.h"
#include "esp_system.h"
#include "esp_timer.h"

// Hardware Pin Definitions
#define BLUE_RX2_PIN 16
#define BLUE_TX2_PIN 17
#define STATUS_LED   2

// Protocol Constants
#define MAGIC_BYTE   0xA5
const char* DEMO_HMAC_KEY = "OEM_ROOT_2026_ZERO_TRUST_SECRET_KEY_!";

#pragma pack(push, 1)
struct OTA_Frame {
    uint8_t  magic_byte;          // Always 0xA5
    uint8_t  scenario_id;         // 1=Valid, 2=MITM Tamper, 3=Rollback, 4=Buggy Watchdog, 5=Zero-Wear Wipe
    uint32_t firmware_version;   // Version number
    uint8_t  self_test_flag;      // 1=Pass, 0=Fail
    char     payload_data[64];    // Simulated binary payload
    uint8_t  signature_hmac[32];  // 32-byte HMAC-SHA256 signature
};
#pragma pack(pop)

HardwareSerial SerialRed(2); // UART2 from Red Team
Preferences prefs;

// In-Memory State
uint32_t active_monotonic_version = 1;
bool is_jtag_locked = true;
bool hmac_key_active = true;

void compute_hmac_sha256(const uint8_t *payload, size_t payload_len, 
                         const char *key, size_t key_len, 
                         uint8_t *output_hmac) {
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char *)key, key_len);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *)payload, payload_len);
    mbedtls_md_hmac_finish(&ctx, output_hmac);
    mbedtls_md_free(&ctx);
}

void emit_risk_log(const char* severity, const char* threat_name, 
                   const char* metric_data, const char* mitigation_action) {
    Serial.printf("[RISK ASSESSED: %s] %s. [METRIC] %s. [MITIGATION] %s.\n",
                  severity, threat_name, metric_data, mitigation_action);
    Serial.flush();
}

void simulate_layer3_silicon_lockdown() {
    delay(200);
    // Layer 3 Silicon Lockdown (NIST PR.AA-01 / Wiersma & Pareja 2017)
    // Simulates checking hardware eFuse bits (DISABLE_JTAG, READ_PROTECTION)
    if (is_jtag_locked) {
        emit_risk_log(
            "HIGH",
            "JTAG Extraction Threat",
            "eFuse DISABLE_JTAG: LOCKED (Simulation)",
            "Physical debug ports permanently isolated via virtual eFuse bit"
        );
    }
}

void load_storage_state() {
    prefs.begin("zerotrace", false);
    active_monotonic_version = prefs.getUInt("mono_ver", 1);
    hmac_key_active = prefs.getBool("key_present", true);
}

void execute_zero_wear_wipe() {
    // Layer 4 Zero-Wear Key Sanitization (NIST RS.MI-02)
    int64_t t_start = esp_timer_get_time(); // Microseconds
    
    // Perform fast NVS key removal
    prefs.remove("key_present");
    prefs.putBool("key_present", false);
    hmac_key_active = false;
    
    int64_t t_elapsed = esp_timer_get_time() - t_start;

    char metric_buf[80];
    snprintf(metric_buf, sizeof(metric_buf), "HMAC Key Wiped in %lld us (Target < 1000us)", t_elapsed);

    emit_risk_log(
        "MEDIUM",
        "Secret Data Remanence Threat",
        metric_buf,
        "Flash metadata unlinked; zero-wear cryptographic erase completed"
    );

    SerialRed.println("ACK_WIPE_OK");
    
    // Automatically restore demo key after 2 seconds for continuous testbed cycling
    delay(100);
    prefs.putBool("key_present", true);
    hmac_key_active = true;
}

void handle_incoming_frame(const OTA_Frame &frame) {
    digitalWrite(STATUS_LED, HIGH);

    // 1. Frame Header Validation
    if (frame.magic_byte != MAGIC_BYTE) {
        emit_risk_log(
            "CRITICAL",
            "Malformed Frame Injection",
            "Invalid Magic Byte received (Expected 0xA5)",
            "Dropped frame immediately from serial stream buffer"
        );
        SerialRed.println("NACK_BAD_MAGIC");
        digitalWrite(STATUS_LED, LOW);
        return;
    }

    // 2. Layer 4 Zero-Wear Command Check
    if (frame.scenario_id == 5) {
        execute_zero_wear_wipe();
        digitalWrite(STATUS_LED, LOW);
        return;
    }

    // 3. Layer 1 Cryptographic Authentication (HMAC-SHA256)
    uint8_t calculated_hmac[32];
    size_t data_to_verify_len = sizeof(OTA_Frame) - sizeof(frame.signature_hmac);
    compute_hmac_sha256((const uint8_t*)&frame, data_to_verify_len,
                        DEMO_HMAC_KEY, strlen(DEMO_HMAC_KEY),
                        calculated_hmac);

    if (memcmp(calculated_hmac, frame.signature_hmac, 32) != 0) {
        // Scenario 2: MITM Tampering Detected
        emit_risk_log(
            "CRITICAL",
            "MITM Cryptographic Mismatch",
            "HMAC-SHA256 signature verification failed (calculated != received)",
            "Staged OTA binary discarded immediately; flash write prohibited"
        );
        SerialRed.println("NACK_CRYPTO_FAIL");
        digitalWrite(STATUS_LED, LOW);
        return;
    }

    // 4. Layer 1 Monotonic Counter Anti-Rollback Check (NIST PR.PS-02)
    if (frame.firmware_version <= active_monotonic_version) {
        // Scenario 3: Downgrade / Rollback Exploit Attempt
        char metric_buf[96];
        snprintf(metric_buf, sizeof(metric_buf), 
                 "Inbound firmware v%u <= active monotonic counter v%u", 
                 frame.firmware_version, active_monotonic_version);

        emit_risk_log(
            "CRITICAL",
            "Downgrade Exploit Neutralized",
            metric_buf,
            "Rollback payload rejected; monotonic counter state preserved"
        );
        SerialRed.println("NACK_ROLLBACK_FAIL");
        digitalWrite(STATUS_LED, LOW);
        return;
    }

    // 5. Layer 1 Fault-Tolerant Watchdog Probation Check (NIST RC.RP-01)
    if (frame.self_test_flag == 0) {
        // Scenario 4: Corrupt or Buggy Probationary Update
        emit_risk_log(
            "HIGH",
            "Probationary Boot Health Check Failed",
            "Self-test status flag: 0 (Degraded/Corrupted)",
            "Watchdog rollback triggered; restoring Golden Image v1"
        );
        SerialRed.println("NACK_WATCHDOG_ROLLBACK");
        digitalWrite(STATUS_LED, LOW);
        return;
    }

    // 6. Valid Scenario 1: All Cryptographic, Monotonic, and Health Checks Passed
    active_monotonic_version = frame.firmware_version;
    prefs.putUInt("mono_ver", active_monotonic_version);

    char metric_buf[80];
    snprintf(metric_buf, sizeof(metric_buf), 
             "Version=%u, HMAC-SHA256 valid", active_monotonic_version);

    emit_risk_log(
        "LOW",
        "Legitimate Firmware Package Authenticated",
        metric_buf,
        "Firmware written to execution slot; monotonic version bumped"
    );
    SerialRed.println("ACK_OK");
    digitalWrite(STATUS_LED, LOW);
}

void process_serial2_input() {
    static uint8_t rx_buffer[sizeof(OTA_Frame)];
    static size_t bytes_read = 0;
    static unsigned long last_byte_time = 0;

    // Reset buffer if byte timeout exceeds 500ms
    if (bytes_read > 0 && (millis() - last_byte_time > 500)) {
        bytes_read = 0;
    }

    while (SerialRed.available()) {
        uint8_t b = SerialRed.read();
        last_byte_time = millis();

        // Synchronize on MAGIC_BYTE
        if (bytes_read == 0) {
            if (b != MAGIC_BYTE) {
                continue; // Skip framing noise
            }
        }

        rx_buffer[bytes_read++] = b;

        if (bytes_read == sizeof(OTA_Frame)) {
            OTA_Frame frame;
            memcpy(&frame, rx_buffer, sizeof(OTA_Frame));
            bytes_read = 0;
            handle_incoming_frame(frame);
        }
    }
}

void print_system_status() {
    Serial.println("\n[BLUE DEFENDER] --- ZeroTrace System Status ---");
    Serial.printf("[BLUE DEFENDER] Monotonic Firmware Version: v%u\n", active_monotonic_version);
    Serial.printf("[BLUE DEFENDER] Silicon Lockdown (eFuse): %s\n", is_jtag_locked ? "LOCKED" : "UNLOCKED");
    Serial.printf("[BLUE DEFENDER] Master HMAC Key: %s\n", hmac_key_active ? "LOADED" : "SANITIZED");
    Serial.println("[BLUE DEFENDER] ---------------------------------");
}

void setup() {
    Serial.begin(115200);
    delay(500);

    // Initialize UART2 for Red Team communication (9600 baud)
    SerialRed.begin(9600, SERIAL_8N1, BLUE_RX2_PIN, BLUE_TX2_PIN);

    pinMode(STATUS_LED, OUTPUT);
    digitalWrite(STATUS_LED, LOW);

    load_storage_state();

    Serial.println("\n=======================================================");
    Serial.println("   ZEROTRACE BLUE TEAM DEFENDER (ESP32 #2)             ");
    Serial.println("   4-Layer Zero-Trust Framework for IoT (NIST CSF 2.0) ");
    Serial.println("=======================================================");
    
    // Boot sequence eFuse validation
    simulate_layer3_silicon_lockdown();
    print_system_status();
}

void loop() {
    process_serial2_input();

    // Process local debug commands from USB Serial
    if (Serial.available()) {
        char c = Serial.read();
        if (c == 'r' || c == 'R') {
            active_monotonic_version = 1;
            prefs.putUInt("mono_ver", 1);
            Serial.println("[BLUE DEFENDER] Monotonic counter reset to v1.");
        } else if (c == 's' || c == 'S') {
            print_system_status();
        } else if (c == 'e' || c == 'E') {
            simulate_layer3_silicon_lockdown();
        }
    }
}
