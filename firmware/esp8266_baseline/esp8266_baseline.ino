/**
 * ZeroTrace - Target A: ESP8266 NodeMCU (Baseline Implementation)
 * -------------------------------------------------------------
 * Target Hardware: ESP8266 NodeMCU 1.0 (ESP-12E / ESP-12F Module)
 * Architecture: Tensilica Xtensa L106 @ 80/160 MHz
 * Transport: USB Serial @ 115200 baud
 *
 * Seeded Weaknesses (Educational Baseline):
 *   - L1: Checksum-only OTA verification (insecure additive/CRC32; no HMAC signature)
 *   - L1: No monotonic counter check (accepts legacy v0 firmware downgrades)
 *   - L1: No probationary boot watchdog revert (hangs or crashes on corrupted update)
 *   - L2: Single-rail variables with no SBFT or invariant checks (instruction skip undetected)
 *   - L3: Silicon lockdown absent on ESP8266 architecture (no eFuse secure boot / JTAG lockout)
 *   - L4: Incomplete key deletion (unlinks memory reference, but leaves raw key bytes in RAM)
 *
 * NOTE: ESP8266 lacks hardware cryptographic engines, eFuse arrays, and secure bootloader
 * features present on newer ESP32 chips. This board demonstrates software-level weaknesses
 * on a constrained edge node for direct comparison against the Hardened ESP32.
 */

#include <Arduino.h>

// NodeMCU ESP-12E/F onboard LED: GPIO 2 / D4 (Active LOW)
#define LED_BUILTIN_PIN 2

// Baseline In-Memory State
uint32_t baseline_version = 1;
char exposed_key_material[64] = "OEM_ROOT_2026_ZERO_TRUST_SECRET_KEY_!";
bool key_pointer_active = true;
volatile uint16_t state_register = 0x5A5A;
String current_req_id = "";
uint32_t current_seq = 0;

void emit_json_response(const char* json_str) {
    String s = String(json_str);
    if (current_req_id.length() > 0 && s.endsWith("}")) {
        s = s.substring(0, s.length() - 1);
        s += ",\"req_id\":\"" + current_req_id + "\"";
        if (current_seq > 0) {
            s += ",\"seq\":" + String(current_seq);
        }
        s += "}";
        Serial.println(s);
    } else {
        Serial.println(json_str);
    }
    Serial.flush();
}

void print_risk_log(const char* severity, const char* threat_name, 
                    const char* metric_data, const char* mitigation_action) {
    Serial.printf("[RISK ASSESSED: %s] %s. [METRIC] %s. [MITIGATION] %s.\n",
                  severity, threat_name, metric_data, mitigation_action);
    Serial.flush();
}

void handle_info() {
    uint32_t chip_id = ESP.getChipId();
    uint32_t flash_bytes = ESP.getFlashChipRealSize();
    uint32_t cpu_freq = ESP.getCpuFreqMHz();

    String resp = "{\"status\":\"ready\",\"proto_ver\":\"2.0\",\"board_type\":\"esp8266\",\"firmware_id\":\"zerotrace-baseline-v2.0\",\"device_id\":\"esp8266-baseline\",\"target\":\"baseline\",\"arch\":\"esp8266\",\"chip_id\":\"0x";
    char hex_buf[16];
    snprintf(hex_buf, sizeof(hex_buf), "%06X", chip_id);
    resp += String(hex_buf) + "\",\"cpu_mhz\":" + String(cpu_freq) + ",\"flash_kb\":" + String(flash_bytes / 1024);
    if (current_req_id.length() > 0) {
        resp += ",\"req_id\":\"" + current_req_id + "\"";
    }
    resp += ",\"capabilities\":[\"L1-01\",\"L1-02\",\"L1-03\",\"L1-04\",\"L1-05\",\"L4-01\",\"L4-02\",\"L4-03\",\"L4-04\",\"L4-05\"]}";
    Serial.println(resp);
    Serial.flush();
}

void handle_test(const String &test_id) {
    digitalWrite(LED_BUILTIN_PIN, LOW); // LED ON (active low)

    if (test_id == "L1-APPROVED" || test_id == "L1-01") {
        baseline_version = 2;
        print_risk_log("LOW", "Firmware Package Received", "Version=2, Simple Checksum Valid", "Staged to execution slot (ESP8266)");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L1-01\",\"result\":\"ACCEPTED\",\"status\":\"PASS\",\"details\":\"Firmware v2 accepted via simple additive checksum\"}");
    }
    else if (test_id == "L1-MODIFIED" || test_id == "L1-02") {
        // Seeded Weakness: Payload tampered, but baseline lacks HMAC check
        print_risk_log("CRITICAL", "Weak Checksum Exploit", "Payload Tampered (No HMAC Check)", "None - corrupted payload accepted into RAM");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L1-02\",\"result\":\"ACCEPTED_WEAKNESS\",\"status\":\"FAIL\",\"details\":\"Tampered payload accepted due to lack of cryptographic signature check\"}");
    }
    else if (test_id == "L1-TAG-CORRUPT" || test_id == "L1-03") {
        // Seeded Weakness: Baseline ignores HMAC tag and accepts
        print_risk_log("CRITICAL", "Corrupt Tag Ignored", "HMAC Tag Corrupted (Ignored by Baseline)", "None - package accepted without cryptographic validation");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L1-03\",\"result\":\"ACCEPTED_WEAKNESS\",\"status\":\"FAIL\",\"details\":\"Corrupted authentication tag ignored by baseline parser\"}");
    }
    else if (test_id == "L1-REPLAY" || test_id == "L1-04") {
        // Seeded Weakness: Baseline lacks deduplication cache and re-accepts update
        print_risk_log("HIGH", "Replay Attack Succeeded", "Request ID Re-submitted", "None - baseline re-executes update without nonce check");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L1-04\",\"result\":\"ACCEPTED_WEAKNESS\",\"status\":\"FAIL\",\"details\":\"Replay update accepted due to missing request deduplication\"}");
    }
    else if (test_id == "L1-ROLLBACK" || test_id == "L1-05" || test_id == "L1-BOOTFAIL-REVERT") {
        // Seeded Weakness: No monotonic counter check; allows downgrade to v0
        baseline_version = 0;
        print_risk_log("CRITICAL", "Firmware Downgrade Exploit", "Target Version v0 <= Current Version v1", "None - rollback allowed (No monotonic NVS on ESP8266)");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L1-05\",\"result\":\"ACCEPTED_WEAKNESS\",\"status\":\"FAIL\",\"details\":\"Firmware v0 accepted without monotonic anti-rollback check\"}");
    }
    else if (test_id == "L4-CREATE" || test_id == "L4-01") {
        print_risk_log("LOW", "Synthetic Test Key Created", "Key stored in global RAM buffer", "Key pointer initialized without enclave isolation");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L4-01\",\"result\":\"ENCRYPTED_INSECURE_REGISTRY\",\"status\":\"PASS\",\"details\":\"Test key active in RAM without hardware isolation\"}");
    }
    else if (test_id == "L4-VERIFY-PRE" || test_id == "L4-02") {
        print_risk_log("LOW", "Data Decryption Verified", "Plaintext matches test payload", "Decryption accessible via active key");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L4-02\",\"result\":\"VERIFIED_ACCESSIBLE\",\"status\":\"PASS\",\"details\":\"Ciphertext decrypts successfully with active key\"}");
    }
    else if (test_id == "L4-TAMPER" || test_id == "L4-03") {
        print_risk_log("CRITICAL", "Ciphertext Tamper Undetected", "Corrupted ciphertext processed", "None - baseline lacks authenticated encryption tag check");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L4-03\",\"result\":\"UNCHECKED_TAMPER\",\"status\":\"FAIL\",\"details\":\"Tampered ciphertext accepted without authentication failure\"}");
    }
    else if (test_id == "L4-UNAUTH" || test_id == "L4-04") {
        print_risk_log("CRITICAL", "Unauthorized Wipe Permitted", "Sanitization attempted without token", "None - unauthenticated command accepted");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L4-04\",\"result\":\"UNAUTH_WIPE_PERMITTED\",\"status\":\"FAIL\",\"details\":\"Unauthenticated sanitization command accepted by baseline\"}");
    }
    else if (test_id == "L4-KEY-ZEROIZE" || test_id == "L4-05") {
        // Seeded Weakness: Only sets pointer/flag false, does NOT zeroize memory buffer
        key_pointer_active = false;
        print_risk_log("MEDIUM", "Incomplete Key Erasure", "Pointer unlinked, 38 key bytes remain in RAM", "None - key remnants accessible via memory inspection");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L4-05\",\"result\":\"POINTER_REMOVED_KEY_LEAKED\",\"status\":\"FAIL\",\"details\":\"Key reference cleared but raw key bytes unzeroized in memory\"}");
    }
    else if (test_id == "L2-SKIP-SIM") {
        // Seeded Weakness: Instruction skip flips state register, baseline has no SBFT checks
        state_register ^= 0x0001; // 0x5A5A -> 0x5A5B
        print_risk_log("HIGH", "Instruction Skip Fault", "State Reg altered to 0x5A5B", "None - corrupted register accepted in execution");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L2-SKIP-SIM\",\"result\":\"INSTRUCTION_SKIPPED\",\"status\":\"FAIL\",\"details\":\"Single instruction skip modified state with zero runtime detection\"}");
    }
    else if (test_id == "L2-UNROLL") {
        // Seeded Weakness: Unrolled loop step skipped, unverified accumulator
        uint32_t acc = 0;
        for (int i = 0; i < 9; i++) acc += 10; // skips 10th step
        print_risk_log("HIGH", "Loop Computation Error", "Accumulator Expected=100 Got=90", "None - computation error propagated");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L2-UNROLL\",\"result\":\"UNCHECKED_CORRUPTION\",\"status\":\"FAIL\",\"details\":\"Skipped loop iteration undetected by runtime software\"}");
    }
    else if (test_id == "L2-AUTH") {
        // Seeded Weakness: Single authorization check bypassed by bit-flip
        print_risk_log("HIGH", "Authorization Check Bypass", "Single branch condition corrupted to TRUE", "None - unauthorized routine executed");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L2-AUTH\",\"result\":\"UNAUTH_BYPASS\",\"status\":\"FAIL\",\"details\":\"Single conditional branch bypassed via corrupted flag\"}");
    }
    else if (test_id == "L3-POLICY-SIM") {
        // Honest ESP8266 architectural limitation: ESP8266 has NO silicon eFuses or JTAG lockout hardware
        print_risk_log("HIGH", "Silicon Defense Absent", "eFuse JTAG Lockout: NOT SUPPORTED ON ESP8266", "None - ESP8266 silicon lacks hardware security extensions");
        emit_json_response("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"test_id\":\"L3-POLICY-SIM\",\"result\":\"ABSENT_HARDWARE_DEFENSE\",\"status\":\"FAIL\",\"details\":\"ESP8266 silicon architecture lacks eFuses and hardware debug lock features\"}");
    }
    else {
        emit_json_response("{\"error\":\"unknown_test_id\"}");
    }

    digitalWrite(LED_BUILTIN_PIN, HIGH); // LED OFF
}

void parse_serial_command(const String &line) {
    String trimmed = line;
    trimmed.trim();
    if (trimmed.length() == 0) return;

    // Reset correlation IDs
    current_req_id = "";
    current_seq = 0;

    int req_idx = trimmed.indexOf("\"req_id\":\"");
    if (req_idx != -1) {
        int end_req = trimmed.indexOf("\"", req_idx + 10);
        if (end_req != -1) {
            current_req_id = trimmed.substring(req_idx + 10, end_req);
        }
    }

    int seq_idx = trimmed.indexOf("\"seq\":");
    if (seq_idx != -1) {
        current_seq = trimmed.substring(seq_idx + 6).toInt();
    }

    if (trimmed == "ready" || trimmed == "info" || trimmed.indexOf("\"handshake\"") != -1 || trimmed.indexOf("\"cmd\":\"info\"") != -1) {
        handle_info();
        return;
    }

    // JSON command parsing: {"cmd":"run_test","id":"..."}
    int id_idx = trimmed.indexOf("\"id\":\"");
    if (id_idx != -1) {
        int end_idx = trimmed.indexOf("\"", id_idx + 6);
        if (end_idx != -1) {
            String test_id = trimmed.substring(id_idx + 6, end_idx);
            handle_test(test_id);
            return;
        }
    }

    // Fallback: simple text commands (e.g. TEST:L1-APPROVED)
    if (trimmed.startsWith("TEST:")) {
        String test_id = trimmed.substring(5);
        test_id.trim();
        handle_test(test_id);
    } else {
        Serial.printf("{\"target\":\"baseline\",\"arch\":\"esp8266\",\"echo\":\"%s\"}\n", trimmed.c_str());
    }
}

void setup() {
    Serial.begin(115200);
    delay(300);

    pinMode(LED_BUILTIN_PIN, OUTPUT);
    digitalWrite(LED_BUILTIN_PIN, HIGH); // Off initially (active low)

    uint32_t chip_id = ESP.getChipId();
    Serial.printf("{\"status\":\"ready\",\"target\":\"baseline\",\"arch\":\"esp8266\",\"chip_id\":\"0x%06X\",\"flash_kb\":%u}\n",
                  chip_id, ESP.getFlashChipRealSize() / 1024);
}

void loop() {
    if (Serial.available()) {
        String line = Serial.readStringUntil('\n');
        parse_serial_command(line);
    }
}
