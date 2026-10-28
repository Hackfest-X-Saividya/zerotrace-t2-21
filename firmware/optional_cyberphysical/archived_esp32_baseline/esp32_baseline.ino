/**
 * ZeroTrace - ESP32 Target A: Baseline Implementation
 * -------------------------------------------------------------
 * Target Hardware: ESP32 DevKit V1 / NodeMCU (Target A)
 * Transports: USB Serial @ 115200 baud
 *
 * Seeded Weaknesses (Educational Baseline):
 *   - L1: Checksum-only verification (no HMAC signature enforcement)
 *   - L1: No monotonic counter check (vulnerable to firmware rollback/downgrades)
 *   - L1: No probationary boot watchdog revert (hangs or crashes on corrupt update)
 *   - L2: Single-rail variables with no SBFT or invariant checks (instruction skip undetected)
 *   - L3: Unprotected simulated debug-lock state (insecure policy configuration)
 *   - L4: Incomplete key deletion (unlinks pointer but leaves raw key bytes in memory)
 */

#include <Arduino.h>
#include "../common/pins_config.h"

ChipHardwareInfo chip_info;
uint32_t baseline_version = 1;
char exposed_key_material[64] = "OEM_ROOT_2026_ZERO_TRUST_SECRET_KEY_!";
bool key_pointer_active = true;
volatile uint16_t state_register = 0x5A5A;

void emit_json_response(const char* json_str) {
    Serial.println(json_str);
    Serial.flush();
}

void print_risk_log(const char* severity, const char* threat_name, 
                    const char* metric_data, const char* mitigation_action) {
    Serial.printf("[RISK ASSESSED: %s] %s. [METRIC] %s. [MITIGATION] %s.\n",
                  severity, threat_name, metric_data, mitigation_action);
    Serial.flush();
}

void handle_info() {
    Serial.printf("{\"status\":\"info\",\"target\":\"baseline\",\"chip\":\"%s\",\"rev\":%u,\"flash_kb\":%u,\"has_psram\":%s,\"uart_rx\":%u,\"uart_tx\":%u}\n",
                  chip_info.model, chip_info.revision, chip_info.flash_size_bytes / 1024,
                  chip_info.has_psram ? "true" : "false",
                  chip_info.uart2_rx, chip_info.uart2_tx);
}

void handle_test(const String &test_id) {
    if (test_id == "L1-APPROVED") {
        baseline_version = 2;
        print_risk_log("LOW", "Firmware Package Received", "Version=2, Simple Checksum Valid", "Staged to execution slot");
        emit_json_response("{\"target\":\"baseline\",\"test_id\":\"L1-APPROVED\",\"result\":\"ACCEPTED\",\"status\":\"PASS\",\"details\":\"Firmware v2 accepted via simple checksum\"}");
    }
    else if (test_id == "L1-MODIFIED") {
        // Seeded Weakness: Payload tampered, but baseline lacks HMAC check
        print_risk_log("CRITICAL", "Weak Checksum Exploit", "Payload Tampered (No HMAC Check)", "None - corrupted payload accepted");
        emit_json_response("{\"target\":\"baseline\",\"test_id\":\"L1-MODIFIED\",\"result\":\"ACCEPTED_WEAKNESS\",\"status\":\"FAIL\",\"details\":\"Tampered payload accepted due to lack of cryptographic signature check\"}");
    }
    else if (test_id == "L1-ROLLBACK") {
        // Seeded Weakness: No monotonic counter check; allows downgrade to v0
        baseline_version = 0;
        print_risk_log("CRITICAL", "Firmware Downgrade Exploit", "Target Version v0 <= Current Version v1", "None - rollback allowed");
        emit_json_response("{\"target\":\"baseline\",\"test_id\":\"L1-ROLLBACK\",\"result\":\"ACCEPTED_WEAKNESS\",\"status\":\"FAIL\",\"details\":\"Firmware v0 accepted without monotonic anti-rollback check\"}");
    }
    else if (test_id == "L1-BOOTFAIL-REVERT") {
        // Seeded Weakness: Probation self-test fails, but baseline has no watchdog rollback
        print_risk_log("HIGH", "Probationary Boot Failure", "Self-test flag: 0 (Failed)", "None - system hangs indefinitely without rollback");
        emit_json_response("{\"target\":\"baseline\",\"test_id\":\"L1-BOOTFAIL-REVERT\",\"result\":\"HANGS_OR_CRASHES\",\"status\":\"FAIL\",\"details\":\"Device remains trapped in faulty boot without golden image revert\"}");
    }
    else if (test_id == "L4-KEY-ZEROIZE") {
        // Seeded Weakness: Only sets pointer/flag false, does NOT zeroize memory buffer
        key_pointer_active = false;
        print_risk_log("MEDIUM", "Incomplete Key Erasure", "Pointer unlinked, 38 key bytes remain in RAM", "None - key remnants accessible via memory inspection");
        emit_json_response("{\"target\":\"baseline\",\"test_id\":\"L4-KEY-ZEROIZE\",\"result\":\"POINTER_REMOVED_KEY_LEAKED\",\"status\":\"FAIL\",\"details\":\"Key reference cleared but raw key bytes unzeroized in memory\"}");
    }
    else if (test_id == "L2-SKIP-SIM") {
        // Seeded Weakness: Instruction skip flips state register, baseline has no SBFT checks
        state_register ^= 0x0001; // 0x5A5A -> 0x5A5B
        print_risk_log("HIGH", "Instruction Skip Fault", "State Reg altered to 0x5A5B", "None - corrupted register accepted in execution");
        emit_json_response("{\"target\":\"baseline\",\"test_id\":\"L2-SKIP-SIM\",\"result\":\"INSTRUCTION_SKIPPED\",\"status\":\"FAIL\",\"details\":\"Single instruction skip modified state with zero runtime detection\"}");
    }
    else if (test_id == "L2-UNROLL") {
        // Seeded Weakness: Unrolled loop step skipped, unverified accumulator
        uint32_t acc = 0;
        for (int i = 0; i < 9; i++) acc += 10; // skips 10th step
        print_risk_log("HIGH", "Loop Computation Error", "Accumulator Expected=100 Got=90", "None - computation error propagated");
        emit_json_response("{\"target\":\"baseline\",\"test_id\":\"L2-UNROLL\",\"result\":\"UNCHECKED_CORRUPTION\",\"status\":\"FAIL\",\"details\":\"Skipped loop iteration undetected by runtime software\"}");
    }
    else if (test_id == "L2-AUTH") {
        // Seeded Weakness: Single authorization check bypassed by bit-flip
        uint8_t auth_flag = 0x01; // Bypassed
        print_risk_log("HIGH", "Authorization Check Bypass", "Single branch condition corrupted to TRUE", "None - unauthorized routine executed");
        emit_json_response("{\"target\":\"baseline\",\"test_id\":\"L2-AUTH\",\"result\":\"UNAUTH_BYPASS\",\"status\":\"FAIL\",\"details\":\"Single conditional branch bypassed via corrupted flag\"}");
    }
    else if (test_id == "L3-POLICY-SIM") {
        // Seeded Weakness: Insecure debug policy simulation
        print_risk_log("HIGH", "Simulated Debug Port Unlocked", "Debug Policy Register: 0x00 (UNLOCKED)", "None - physical tap controllers accessible");
        emit_json_response("{\"target\":\"baseline\",\"test_id\":\"L3-POLICY-SIM\",\"result\":\"UNLOCKED_DEBUG_LEAK\",\"status\":\"FAIL\",\"details\":\"Simulated JTAG debug interface remains accessible at boot\"}");
    }
    else {
        emit_json_response("{\"error\":\"unknown_test_id\"}");
    }
}

void parse_serial_command(const String &line) {
    String trimmed = line;
    trimmed.trim();
    if (trimmed.length() == 0) return;

    if (trimmed == "ready" || trimmed == "info") {
        handle_info();
        return;
    }

    // Check for JSON test command format: {"cmd":"run_test","id":"..."}
    int id_idx = trimmed.indexOf("\"id\":\"");
    if (id_idx != -1) {
        int end_idx = trimmed.indexOf("\"", id_idx + 6);
        if (end_idx != -1) {
            String test_id = trimmed.substring(id_idx + 6, end_idx);
            handle_test(test_id);
            return;
        }
    }

    // Fallback: simple text commands
    if (trimmed.startsWith("TEST:")) {
        String test_id = trimmed.substring(5);
        test_id.trim();
        handle_test(test_id);
    } else {
        Serial.printf("{\"target\":\"baseline\",\"echo\":\"%s\"}\n", trimmed.c_str());
    }
}

void setup() {
    Serial.begin(115200);
    delay(400);

    chip_info = inspect_chip_hardware();

    pinMode(STATUS_LED_PIN, OUTPUT);
    digitalWrite(STATUS_LED_PIN, LOW);

    // Announce ready state
    Serial.printf("{\"status\":\"ready\",\"target\":\"baseline\",\"chip\":\"%s\",\"rev\":%u,\"has_psram\":%s}\n",
                  chip_info.model, chip_info.revision, chip_info.has_psram ? "true" : "false");
}

void loop() {
    if (Serial.available()) {
        String line = Serial.readStringUntil('\n');
        parse_serial_command(line);
    }
}
