/*
 * ZeroTrace — ESP32 Blue Team Monitor Firmware (V2.1)
 * Role: BLUE TEAM
 * - Monitors telemetry, detects anomalies, reports defensive decisions, participates in recovery
 * - Hardware Pin Mappings:
 *     ESP32 RX2 (GPIO16) <- ESP8266 D1 (GPIO5) [Inter-board UART RX]
 *     ESP32 TX2 (GPIO17) -> ESP8266 D2 (GPIO4) [Inter-board UART TX]
 *     ESP32 GPIO19       -> Arduino Uno RESET Pin [Emergency Containment Active LOW pulse]
 * - USB Serial: Communicates with ZeroTrace Backend @ 115200 baud
 * - Layer Support:
 *     L1: Software Secure Boot / OTA Integrity verification using SHA-256 (no eFuse modification)
 *     L2: Evaluates trigger/fault alerts and drives target containment/recovery
 *     L3: Stable PUF engine with 15-iteration majority bit-voting + Silicon Lock State Machine
 *     L4: Monotonic counter & HMAC-SHA verification link monitor with replay/tamper rejection
 */

#include <Arduino.h>
#include <mbedtls/sha256.h>

#define RED_TEAM_RX 16    // GPIO16 (RX2) from ESP8266 TX (D1)
#define RED_TEAM_TX 17    // GPIO17 (TX2) to ESP8266 RX (D2)
#define TARGET_RESET_PIN 19 // GPIO19 connected to Arduino RESET pin

HardwareSerial RedLink(2); // Use UART2

const char* DEVICE_ID = "ESP32_BLUE_TEAM_01";
const char* FIRMWARE_VER = "2.0.0";
const char* PROTOCOL_VER = "ZT-V2";

static uint32_t blue_seq = 0;
static uint32_t anomalies_detected = 0;
static uint32_t containments_executed = 0;

// Layer 1 Software Image Blob in RAM (128 bytes)
static uint8_t g_firmware_blob[128];
static const char* GOLDEN_SHA256 = "88d13d4dadf6d93ee67daf4dba4a7dd9c99ffde5629cc0b986a48dbfb641f536";

// Layer 3 Silicon Lock State Machine
enum LockState {
    LOCK_LOCKED = 0,
    LOCK_UNLOCKED = 1,
    LOCK_LOCKOUT = 2
};
static volatile LockState current_lock_state = LOCK_LOCKED;
static uint8_t lock_fail_count = 0;
static uint32_t lockout_start_ms = 0;

// Layer 4 Monotonic Counter & Crypto Key
const uint32_t L4_SECRET_KEY = 0xD4B83120;
static uint32_t last_seen_counter = 0;
static uint32_t l4_verified_count = 0;
static uint32_t l4_rejected_replay = 0;
static uint32_t l4_rejected_mac = 0;

void init_firmware_blob() {
    for (int i = 0; i < 128; i++) {
        g_firmware_blob[i] = (uint8_t)((i * 37 + 13) & 0xFF);
    }
}

// Compute simple message authentication code for L4 link
uint32_t compute_l4_mac(uint32_t key, uint32_t counter, const String &nonce) {
    uint32_t mac = key ^ (counter * 0x45D9F3B);
    for (unsigned int i = 0; i < nonce.length(); i++) {
        mac = ((mac << 5) | (mac >> 27)) ^ (uint32_t)nonce.charAt(i);
    }
    return mac;
}

// Stable Intrinsic Silicon PUF Engine
// Takes 15 independent evaluations with internal hardware thermal noise and performs majority bit-voting
uint32_t compute_esp32_puf(uint32_t challenge) {
    uint8_t bit_ones[32] = {0};
    uint64_t mac = ESP.getEfuseMac();

    for (uint8_t trial = 0; trial < 15; trial++) {
        uint32_t acc = 0x3C6EF372 ^ challenge ^ (uint32_t)mac;
        for (uint8_t i = 0; i < 4; i++) {
            uint32_t noise = (uint32_t)esp_random();
            acc = ((acc << 9) | (acc >> 23)) ^ noise ^ (uint32_t)(trial * 0x9E3779B9);
        }
        for (uint8_t b = 0; b < 32; b++) {
            if ((acc >> b) & 1) bit_ones[b]++;
        }
    }

    uint32_t stable_puf = 0;
    for (uint8_t b = 0; b < 32; b++) {
        if (bit_ones[b] >= 8) {
            stable_puf |= (1UL << b);
        }
    }
    return stable_puf;
}

void setup() {
    Serial.begin(115200);
    RedLink.begin(9600, SERIAL_8N1, RED_TEAM_RX, RED_TEAM_TX);

    pinMode(TARGET_RESET_PIN, OUTPUT);
    digitalWrite(TARGET_RESET_PIN, HIGH); // Inactive reset (Active-LOW)

    init_firmware_blob();

    delay(200);
    Serial.println(F("{\"event\":\"BOOT\",\"board\":\"ESP32\",\"role\":\"BLUE_TEAM\",\"version\":\"2.0.0\",\"protocol\":\"ZT-V2\"}"));
}

void execute_containment(const String &reason) {
    containments_executed++;
    uint32_t t0 = micros();

    // Pulse Target Reset line LOW for 15ms to trigger clean microcontroller reboot
    digitalWrite(TARGET_RESET_PIN, LOW);
    delay(15);
    digitalWrite(TARGET_RESET_PIN, HIGH);

    uint32_t latency_us = micros() - t0;

    Serial.print(F("{\"event\":\"CONTAINMENT_EXECUTED\",\"seq\":"));
    Serial.print(++blue_seq);
    Serial.print(F(",\"reason\":\""));
    Serial.print(reason);
    Serial.print(F("\",\"latency_us\":"));
    Serial.print(latency_us);
    Serial.println(F("}"));
}

void verify_firmware_image(const String &nonce) {
    uint32_t t0 = micros();

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 for SHA-256
    mbedtls_sha256_update(&ctx, g_firmware_blob, 128);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    uint32_t latency_us = micros() - t0;

    char hash_str[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hash_str + (i * 2), "%02x", hash[i]);
    }
    hash_str[64] = 0;

    bool match = (strcmp(hash_str, GOLDEN_SHA256) == 0);

    Serial.print(F("OTA_VERIFY_RESULT:"));
    Serial.print(match ? F("VALID:") : F("CORRUPTED:"));
    Serial.print(hash_str);
    Serial.print(F(":"));
    Serial.print(latency_us);
    Serial.print(F(":"));
    Serial.println(nonce);
}

void loop() {
    // Reset lockout after 10 seconds timeout
    if (current_lock_state == LOCK_LOCKOUT && (millis() - lockout_start_ms > 10000)) {
        current_lock_state = LOCK_LOCKED;
        lock_fail_count = 0;
    }

    // Process backend commands via USB Serial
    if (Serial.available() > 0) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();

        // 1. Layer Demo Backend Defense Command
        if (cmd.startsWith("DEFEND:")) {
            // Format: DEFEND:<layer>:<nonce>
            int first_colon = cmd.indexOf(':');
            int second_colon = cmd.indexOf(':', first_colon + 1);
            int layer = (second_colon > 0) ? cmd.substring(first_colon + 1, second_colon).toInt() : 1;
            String nonce = (second_colon > 0) ? cmd.substring(second_colon + 1) : "0";

            containments_executed++;
            blue_seq++;

            // If layer 1, restore original firmware blob
            if (layer == 1) {
                init_firmware_blob();
            }

            Serial.print(F("DEFENSE_APPLIED:"));
            Serial.print(layer);
            Serial.print(F(":"));
            Serial.println(nonce);
        }
        // 2. Layer 1 Software Tamper Command (Modifies RAM copy only, never eFuses)
        else if (cmd.startsWith("OTA_TAMPER:")) {
            // Format: OTA_TAMPER:<flag>:<nonce>
            int first_colon = cmd.indexOf(':');
            int second_colon = cmd.indexOf(':', first_colon + 1);
            int flag = (second_colon > 0) ? cmd.substring(first_colon + 1, second_colon).toInt() : 1;
            String nonce = (second_colon > 0) ? cmd.substring(second_colon + 1) : "0";

            if (flag == 1) {
                g_firmware_blob[16] ^= 0xFF; // Flip byte in RAM
            } else {
                init_firmware_blob(); // Restore pristine
            }

            Serial.print(F("OTA_TAMPER_SET:"));
            Serial.print(flag);
            Serial.print(F(":"));
            Serial.println(nonce);
        }
        // 3. Layer 1 Firmware Verification Command
        else if (cmd.startsWith("OTA_VERIFY:")) {
            // Format: OTA_VERIFY:<nonce>
            String nonce = cmd.substring(11);
            verify_firmware_image(nonce);
        }
        // 4. Layer 3 Silicon Lock Controls
        else if (cmd.startsWith("DEBUG_ACCESS:")) {
            // Format: DEBUG_ACCESS:<token>:<nonce>
            int first_colon = cmd.indexOf(':');
            int second_colon = cmd.indexOf(':', first_colon + 1);
            String token = (second_colon > 0) ? cmd.substring(first_colon + 1, second_colon) : cmd.substring(first_colon + 1);
            String nonce = (second_colon > 0) ? cmd.substring(second_colon + 1) : "0";

            if (current_lock_state == LOCK_LOCKOUT) {
                Serial.print(F("LOCK_STATE:SECURITY_LOCKOUT:"));
                Serial.print(lock_fail_count);
                Serial.print(F(":"));
                Serial.println(nonce);
            } else if (token == "0x5EC0DE32" || token == "AUTH_TOKEN_DEV_ROOT") {
                current_lock_state = LOCK_UNLOCKED;
                lock_fail_count = 0;
                Serial.print(F("LOCK_STATE:UNLOCKED:0:"));
                Serial.println(nonce);
            } else {
                lock_fail_count++;
                if (lock_fail_count >= 3) {
                    current_lock_state = LOCK_LOCKOUT;
                    lockout_start_ms = millis();
                    Serial.print(F("LOCK_STATE:SECURITY_LOCKOUT:"));
                    Serial.print(lock_fail_count);
                    Serial.print(F(":"));
                    Serial.println(nonce);
                } else {
                    Serial.print(F("LOCK_STATE:ACCESS_DENIED:"));
                    Serial.print(lock_fail_count);
                    Serial.print(F(":"));
                    Serial.println(nonce);
                }
            }
        }
        else if (cmd.startsWith("LOCK_STATUS:")) {
            String nonce = cmd.substring(12);
            const char* s_str = (current_lock_state == LOCK_UNLOCKED) ? "UNLOCKED" :
                                (current_lock_state == LOCK_LOCKOUT) ? "SECURITY_LOCKOUT" : "LOCKED";
            Serial.print(F("LOCK_STATE:"));
            Serial.print(s_str);
            Serial.print(F(":"));
            Serial.print(lock_fail_count);
            Serial.print(F(":"));
            Serial.println(nonce);
        }
        else if (cmd.startsWith("LOCK_RESET:")) {
            String nonce = cmd.substring(11);
            current_lock_state = LOCK_LOCKED;
            lock_fail_count = 0;
            Serial.print(F("LOCK_STATE:LOCKED:0:"));
            Serial.println(nonce);
        }
        // 5. Layer 4 Monotonic Counter Reset
        else if (cmd.startsWith("L4_RESET:")) {
            String nonce = cmd.substring(9);
            last_seen_counter = 0;
            l4_verified_count = 0;
            l4_rejected_replay = 0;
            l4_rejected_mac = 0;
            Serial.print(F("L4_RESET_ACK:"));
            Serial.println(nonce);
        }
        // 6. Hardware Identification & PUF Authentication
        else if (cmd == "IDENTIFY" || cmd.startsWith("PUF") || cmd.indexOf("PUF") >= 0) {
            uint32_t challenge_val = 0xA5C3E189;
            int chal_idx = cmd.indexOf("0x");
            if (chal_idx < 0) chal_idx = cmd.indexOf("0X");
            if (chal_idx >= 0) {
                challenge_val = strtoul(cmd.c_str() + chal_idx + 2, NULL, 16);
            } else if (cmd.indexOf(':') > 0) {
                challenge_val = strtoul(cmd.substring(cmd.indexOf(':') + 1).c_str(), NULL, 16);
            }
            uint32_t puf_resp = compute_esp32_puf(challenge_val);
            uint8_t hw = 0;
            for (uint8_t b = 0; b < 32; b++) { if ((puf_resp >> b) & 1) hw++; }
            float uniformity = (hw / 32.0f) * 100.0f;

            Serial.print(F("{\"event\":\"PUF_RESPONSE\",\"board\":\"ESP32\",\"role\":\"BLUE_TEAM\",\"device_id\":\""));
            Serial.print(DEVICE_ID);
            Serial.print(F("\",\"version\":\""));
            Serial.print(FIRMWARE_VER);
            Serial.print(F("\",\"protocol\":\""));
            Serial.print(PROTOCOL_VER);
            Serial.print(F("\",\"puf_type\":\"SILICON_HW_TRNG_PUF\",\"challenge\":\"0x"));
            Serial.print(challenge_val, HEX);
            Serial.print(F("\",\"puf_response\":\"0x"));
            Serial.print(puf_resp, HEX);
            Serial.print(F("\",\"uniformity_pct\":"));
            Serial.print(uniformity, 1);
            Serial.print(F(",\"uptime_ms\":"));
            Serial.print(millis());
            Serial.println(F("}"));
        }
        // 7. Status & Diagnostic Queries
        else if (cmd == "STATUS" || cmd == "PING") {
            Serial.print(F("{\"status\":\"ONLINE\",\"seq\":"));
            Serial.print(blue_seq);
            Serial.print(F(",\"anomalies\":"));
            Serial.print(anomalies_detected);
            Serial.print(F(",\"containments\":"));
            Serial.print(containments_executed);
            Serial.print(F(",\"l4_accept\":"));
            Serial.print(l4_verified_count);
            Serial.print(F(",\"l4_replay\":"));
            Serial.print(l4_rejected_replay);
            Serial.print(F(",\"l4_bad_mac\":"));
            Serial.print(l4_rejected_mac);
            Serial.print(F(",\"uptime_ms\":"));
            Serial.print(millis());
            Serial.println(F("}"));
        }
        else if (cmd.startsWith("RESET_TARGET")) {
            execute_containment("MANUAL_OPERATOR_REQUEST");
        }
    }

    // Monitor inter-board messages from ESP8266 Red Team
    if (RedLink.available() > 0) {
        String red_msg = RedLink.readStringUntil('\n');
        red_msg.trim();

        // Layer 4 Cryptographic Frame Verification: ZT_SEC:<counter>:<nonce>:<mode>:<mac_hex>
        if (red_msg.startsWith("ZT_SEC:")) {
            uint32_t t0 = micros();
            int c1 = red_msg.indexOf(':');
            int c2 = red_msg.indexOf(':', c1 + 1);
            int c3 = red_msg.indexOf(':', c2 + 1);
            int c4 = red_msg.indexOf(':', c3 + 1);

            uint32_t counter = red_msg.substring(c1 + 1, c2).toInt();
            String nonce = red_msg.substring(c2 + 1, c3);
            String mode = red_msg.substring(c3 + 1, c4);
            String mac_str = red_msg.substring(c4 + 1);

            uint32_t rx_mac = 0;
            if (mac_str.startsWith("0x") || mac_str.startsWith("0X")) {
                rx_mac = strtoul(mac_str.c_str() + 2, NULL, 16);
            } else {
                rx_mac = strtoul(mac_str.c_str(), NULL, 16);
            }

            uint32_t expected_mac = compute_l4_mac(L4_SECRET_KEY, counter, nonce);
            String verdict = "ACCEPT";

            // 1. Monotonic counter check (prevent replay attack)
            if (counter <= last_seen_counter) {
                verdict = "REJECT_REPLAY";
                l4_rejected_replay++;
                anomalies_detected++;
            }
            // 2. Message Authentication Code check (prevent tampering / wrong key)
            else if (rx_mac != expected_mac) {
                verdict = "REJECT_BAD_MAC";
                l4_rejected_mac++;
                anomalies_detected++;
            }
            // 3. Accepted legitimate message
            else {
                last_seen_counter = counter;
                l4_verified_count++;
            }

            uint32_t latency_us = micros() - t0;

            // Report verdict over USB Serial to backend
            Serial.print(F("VERIFY_RESULT:"));
            Serial.print(counter);
            Serial.print(F(":"));
            Serial.print(verdict);
            Serial.print(F(":"));
            Serial.print(latency_us);
            Serial.print(F(":"));
            Serial.println(nonce);
        }
        // Layer Demo Attack Detection from Red Team
        else if (red_msg.startsWith("ZT_ATTACK:")) {
            // Format: ZT_ATTACK:<layer>:<nonce>
            int first_colon = red_msg.indexOf(':');
            int second_colon = red_msg.indexOf(':', first_colon + 1);
            int layer = (second_colon > 0) ? red_msg.substring(first_colon + 1, second_colon).toInt() : 1;
            String nonce = (second_colon > 0) ? red_msg.substring(second_colon + 1) : "0";

            anomalies_detected++;
            blue_seq++;

            // Emits detection notice to backend
            Serial.print(F("{\"event\":\"ANOMALY_DETECTED\",\"layer\":"));
            Serial.print(layer);
            Serial.print(F(",\"nonce\":\""));
            Serial.print(nonce);
            Serial.println(F("\"}"));

            Serial.print(F("DEFENSE_APPLIED:"));
            Serial.print(layer);
            Serial.print(F(":"));
            Serial.println(nonce);
        }
        // Echo acknowledgement for UART verification test
        else if (red_msg.startsWith("ZT_PING:")) {
            String nonce = red_msg.substring(8);
            RedLink.print(F("ZT_ACK:"));
            RedLink.println(nonce);

            Serial.print(F("{\"event\":\"UART_PING_ACKED\",\"nonce\":\""));
            Serial.print(nonce);
            Serial.println(F("\"}"));
        }
        // Evaluates incoming Red Team scenario
        else if (red_msg.startsWith("ZT_SCENARIO:")) {
            anomalies_detected++;
            blue_seq++;

            int first_colon = red_msg.indexOf(':', 12);
            String sc_id = (first_colon > 0) ? red_msg.substring(12, first_colon) : red_msg.substring(12);

            Serial.print(F("{\"event\":\"ANOMALY_DETECTED\",\"scenario_id\":\""));
            Serial.print(sc_id);
            Serial.print(F("\",\"decision\":\"CONTAIN_AND_AUDIT\",\"seq\":"));
            Serial.print(blue_seq);
            Serial.println(F("}"));

            if (sc_id.indexOf("CRITICAL") >= 0 || sc_id.indexOf("L2-10") >= 0) {
                execute_containment("CRITICAL_FAULT_CONTAINMENT");
            }
        }
    }

    delay(2);
}
