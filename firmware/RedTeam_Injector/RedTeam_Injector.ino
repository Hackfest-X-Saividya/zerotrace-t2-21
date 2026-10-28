/**
 * ZeroTrace - Red Team Attack Injector (ESP32 #1)
 * -------------------------------------------------------------
 * Target Hardware: ESP32 DevKit V1 / NodeMCU
 * Transports:
 *   - USB Serial @ 115200 baud (Interactive Attack Control Menu)
 *   - Hardware Serial2 @ 9600 baud (GPIO 17 TX -> Blue RX, GPIO 16 RX <- Blue TX)
 *   - VFI Glitch Output: GPIO 25 (8.5 us pulse to Arduino Uno Pin 2)
 *
 * Demonstrates:
 *   - L1: OTA MITM Tampering, Rollback Downgrade, Buggy Watchdog Probation
 *   - L2: 8.5us Physical Voltage Fault Injection (VFI) Pulse
 *   - L4: Zero-Wear Flash Wipe Command Dispatch
 */

#include <Arduino.h>
#include <HardwareSerial.h>
#include "mbedtls/md.h"

// Hardware Pin Definitions
#define RED_TX2_PIN 17
#define RED_RX2_PIN 16
#define GLITCH_PIN  25
#define STATUS_LED  2

// Protocol Constants
#define MAGIC_BYTE  0xA5
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

HardwareSerial SerialBlue(2); // UART2 to Blue Team

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

void sign_frame(OTA_Frame &frame) {
    // Sign all bytes prior to signature_hmac
    size_t data_to_sign_len = sizeof(OTA_Frame) - sizeof(frame.signature_hmac);
    compute_hmac_sha256((const uint8_t*)&frame, data_to_sign_len, 
                        DEMO_HMAC_KEY, strlen(DEMO_HMAC_KEY), 
                        frame.signature_hmac);
}

void print_banner() {
    Serial.println("\n=======================================================");
    Serial.println("   ZEROTRACE RED TEAM ATTACK INJECTOR (ESP32 #1)      ");
    Serial.println("=======================================================");
    Serial.println("Select Attack Scenario to Inject:");
    Serial.println("  [1] Send Valid Signed OTA Update (v2, Pass Self-Test)");
    Serial.println("  [2] Send MITM Tampered OTA Payload (Tampered HMAC)");
    Serial.println("  [3] Send Firmware Rollback Exploit (v0 < Monotonic)");
    Serial.println("  [4] Send Buggy Probationary Firmware (Self-Test=0)");
    Serial.println("  [5] Send Zero-Wear Flash Wipe Command (Scenario 5)");
    Serial.println("  [6] Inject 8.5us VFI Glitch Pulse (GPIO 25 -> Arduino Pin 2)");
    Serial.println("  [a] Auto-Run Full Attack Suite (Scenarios 1-6)");
    Serial.println("  [h] Print this help menu");
    Serial.println("-------------------------------------------------------");
}

void transmit_frame(const OTA_Frame &frame, const char* attack_desc) {
    Serial.printf("\n[RED INJECTOR] >> Transmitting Scenario %u: %s\n", frame.scenario_id, attack_desc);
    Serial.printf("[RED INJECTOR]    Version: %u | Self-Test Flag: %u | Size: %d bytes\n", 
                  frame.firmware_version, frame.self_test_flag, sizeof(OTA_Frame));
    
    digitalWrite(STATUS_LED, HIGH);
    SerialBlue.write((const uint8_t*)&frame, sizeof(OTA_Frame));
    SerialBlue.flush();
    digitalWrite(STATUS_LED, LOW);

    // Wait up to 1500ms for Blue Team ACK/NACK response
    unsigned long start_wait = millis();
    bool response_received = false;
    Serial.print("[RED INJECTOR] << Blue Team Response: ");
    while (millis() - start_wait < 1500) {
        if (SerialBlue.available()) {
            String resp = SerialBlue.readStringUntil('\n');
            resp.trim();
            if (resp.length() > 0) {
                Serial.println(resp);
                response_received = true;
                break;
            }
        }
        delay(10);
    }
    if (!response_received) {
        Serial.println("(Timeout - No response from Blue Team)");
    }
}

void send_scenario_1() {
    OTA_Frame frame;
    memset(&frame, 0, sizeof(OTA_Frame));
    frame.magic_byte = MAGIC_BYTE;
    frame.scenario_id = 1;
    frame.firmware_version = 2; // Incremented authentic version
    frame.self_test_flag = 1;  // Healthy
    snprintf(frame.payload_data, sizeof(frame.payload_data), "SECURE_FIRMWARE_PAYLOAD_V2_PROD_OK");
    sign_frame(frame);
    transmit_frame(frame, "Valid Authentic OTA Update (v2)");
}

void send_scenario_2() {
    OTA_Frame frame;
    memset(&frame, 0, sizeof(OTA_Frame));
    frame.magic_byte = MAGIC_BYTE;
    frame.scenario_id = 2;
    frame.firmware_version = 2;
    frame.self_test_flag = 1;
    snprintf(frame.payload_data, sizeof(frame.payload_data), "SECURE_FIRMWARE_PAYLOAD_V2_PROD_OK");
    sign_frame(frame); // Valid signature over original payload
    
    // Maliciously tamper with payload in-flight (flip bytes)
    frame.payload_data[0] = 'X';
    frame.payload_data[1] = 'A';
    frame.payload_data[2] = 'T';
    frame.payload_data[3] = 'T';
    frame.payload_data[4] = 'K';
    transmit_frame(frame, "MITM Tampered OTA Payload (Signature Invalidation)");
}

void send_scenario_3() {
    OTA_Frame frame;
    memset(&frame, 0, sizeof(OTA_Frame));
    frame.magic_byte = MAGIC_BYTE;
    frame.scenario_id = 3;
    frame.firmware_version = 0; // Downgrade exploit: v0 < monotonic v1
    frame.self_test_flag = 1;
    snprintf(frame.payload_data, sizeof(frame.payload_data), "OLD_VULNERABLE_LEGACY_IMAGE_V0_EXPLOIT");
    sign_frame(frame); // Valid signature on an outdated vulnerable build
    transmit_frame(frame, "Firmware Rollback Attack (v0 Downgrade Attempt)");
}

void send_scenario_4() {
    OTA_Frame frame;
    memset(&frame, 0, sizeof(OTA_Frame));
    frame.magic_byte = MAGIC_BYTE;
    frame.scenario_id = 4;
    frame.firmware_version = 3;
    frame.self_test_flag = 0; // Deliberate self-test failure
    snprintf(frame.payload_data, sizeof(frame.payload_data), "CORRUPT_PROBATION_IMAGE_BOOT_FAIL");
    sign_frame(frame);
    transmit_frame(frame, "Buggy Probationary Firmware (Watchdog Rollback Trigger)");
}

void send_scenario_5() {
    OTA_Frame frame;
    memset(&frame, 0, sizeof(OTA_Frame));
    frame.magic_byte = MAGIC_BYTE;
    frame.scenario_id = 5;
    frame.firmware_version = 999;
    frame.self_test_flag = 1;
    snprintf(frame.payload_data, sizeof(frame.payload_data), "CMD_ZERO_WEAR_CRYPTO_KEY_PURGE_EXEC");
    sign_frame(frame);
    transmit_frame(frame, "Zero-Wear Flash Key Sanitization Trigger");
}

void inject_8_5us_glitch_pulse() {
    Serial.println("\n[RED INJECTOR] >> [FAULT INJECTION] Arming 8.5us GPIO Glitch Pulse on GPIO 25...");
    
    // IEEE Ruminot et al. / FDTC AVR characterization:
    // 8.5 microseconds high pulse induces single-instruction skip in ATmega328P
    digitalWrite(STATUS_LED, HIGH);
    
    noInterrupts();
    digitalWrite(GLITCH_PIN, HIGH);
    delayMicroseconds(8);
    // Micro-delay tuning for 0.5us remainder at 240MHz ESP32 clock (approx 120 cycles)
    for (volatile int i = 0; i < 28; i++) {
        __asm__ __volatile__("nop");
    }
    digitalWrite(GLITCH_PIN, LOW);
    interrupts();

    digitalWrite(STATUS_LED, LOW);
    Serial.println("[RED INJECTOR] << [PULSE FIRED] 8.5us pulse dispatched to Arduino Digital Pin 2 (INT0).");
    Serial.println("[RED INJECTOR]    Monitor Arduino serial output (115200 baud) for SBFT trap & watchdog trigger.");
}

void run_automated_suite() {
    Serial.println("\n[RED INJECTOR] >>> STARTING AUTOMATED ATTACK SUITE <<<");
    
    send_scenario_1();
    delay(3000);
    
    send_scenario_2();
    delay(3000);
    
    send_scenario_3();
    delay(3000);
    
    send_scenario_4();
    delay(3000);
    
    send_scenario_5();
    delay(3000);
    
    inject_8_5us_glitch_pulse();
    delay(3000);
    
    Serial.println("\n[RED INJECTOR] >>> AUTOMATED ATTACK SUITE COMPLETE <<<");
    print_banner();
}

void setup() {
    Serial.begin(115200);
    delay(500);

    // Initialize UART2 to Blue Team (9600 baud, 8N1)
    SerialBlue.begin(9600, SERIAL_8N1, RED_RX2_PIN, RED_TX2_PIN);

    // Initialize Glitch Output Pin
    pinMode(GLITCH_PIN, OUTPUT);
    digitalWrite(GLITCH_PIN, LOW);

    // Status LED
    pinMode(STATUS_LED, OUTPUT);
    digitalWrite(STATUS_LED, LOW);

    print_banner();
}

void loop() {
    if (Serial.available()) {
        char cmd = Serial.read();
        switch (cmd) {
            case '1': send_scenario_1(); break;
            case '2': send_scenario_2(); break;
            case '3': send_scenario_3(); break;
            case '4': send_scenario_4(); break;
            case '5': send_scenario_5(); break;
            case '6': inject_8_5us_glitch_pulse(); break;
            case 'a': case 'A': run_automated_suite(); break;
            case 'h': case 'H': print_banner(); break;
            case '\r': case '\n': break;
            default:
                Serial.printf("[RED INJECTOR] Unknown command '%c'. Press 'h' for menu.\n", cmd);
                break;
        }
    }
}
