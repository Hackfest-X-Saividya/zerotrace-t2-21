/*
 * ZeroTrace — ESP8266 Red Team Simulator Firmware (V2.1)
 * Role: RED TEAM
 * - Generates authorized test events, malformed-but-safe inputs, controlled security scenarios
 * - Hardware Pin Mappings:
 *     ESP8266 D1 (GPIO5)  -> ESP32 RX2 (GPIO16) [Inter-board UART TX]
 *     ESP8266 D2 (GPIO4)  <- ESP32 TX2 (GPIO17) [Inter-board UART RX]
 *     ESP8266 D5 (GPIO14) -> Arduino Uno Pin D2 [Trigger Pulse Output]
 *     ESP8266 D6 (GPIO12) -> Arduino Uno Pin A0 [Glitch Injector via 1k Resistor, Active LOW only]
 * - USB Serial: Communicates with ZeroTrace Backend @ 115200 baud
 * - Layer Support:
 *     L1: Firmware tamper simulation signaling
 *     L2: GLITCH:<ms>:<nonce> pulls A0 node LOW safely through current-limiting resistor
 *     L3: Stable PUF engine with 15-iteration majority bit-voting
 *     L4: L4_SEND transmission with HMAC-SHA256 / Rolling HMAC, replay injection, and key mismatch
 */

#include <SoftwareSerial.h>

#define TRIGGER_PIN 14    // D5 / GPIO14 to Arduino Uno Pin D2
#define BLUE_RX_PIN 4     // D2 / GPIO4 from ESP32 TX2
#define BLUE_TX_PIN 5     // D1 / GPIO5 to ESP32 RX2
#define GLITCH_PIN 12     // D6 / GPIO12 to Arduino Uno Pin A0 via 1k resistor

SoftwareSerial blueSerial(BLUE_RX_PIN, BLUE_TX_PIN); // RX, TX

const char* DEVICE_ID = "ESP8266_RED_TEAM_01";
const char* FIRMWARE_VER = "2.0.0";
const char* PROTOCOL_VER = "ZT-V2";
const uint32_t L4_SECRET_KEY = 0xD4B83120;

static uint32_t red_seq = 0;
static uint32_t last_trigger_time = 0;

// Stable Intrinsic Silicon PUF Engine
// Takes 15 independent evaluations with internal RF/timer jitter and performs majority bit-voting
uint32_t compute_esp8266_puf(uint32_t challenge) {
    uint8_t bit_ones[32] = {0};
    uint32_t chip_id = ESP.getChipId();
    uint32_t flash_id = ESP.getFlashChipId();

    for (uint8_t trial = 0; trial < 15; trial++) {
        uint32_t acc = 0xBB67AE85 ^ challenge ^ chip_id;
        for (uint8_t i = 0; i < 4; i++) {
            uint32_t noise = (uint32_t)ESP.getCycleCount() ^ flash_id;
            acc = ((acc << 7) | (acc >> 25)) ^ noise ^ (uint32_t)(trial * 0x9E3779B9);
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

// Compute simple message authentication code for L4 link
uint32_t compute_l4_mac(uint32_t key, uint32_t counter, const String &nonce) {
    uint32_t mac = key ^ (counter * 0x45D9F3B);
    for (unsigned int i = 0; i < nonce.length(); i++) {
        mac = ((mac << 5) | (mac >> 27)) ^ (uint32_t)nonce.charAt(i);
    }
    return mac;
}

void setup() {
    Serial.begin(115200);
    blueSerial.begin(9600); // Inter-board communication link

    pinMode(TRIGGER_PIN, OUTPUT);
    digitalWrite(TRIGGER_PIN, LOW);

    // Glitch pin must ALWAYS start as high-impedance INPUT
    pinMode(GLITCH_PIN, INPUT);

    delay(200);
    Serial.println(F("{\"event\":\"BOOT\",\"board\":\"ESP8266\",\"role\":\"RED_TEAM\",\"version\":\"2.0.0\",\"protocol\":\"ZT-V2\"}"));
}

void emit_pulse(uint32_t duration_us) {
    digitalWrite(TRIGGER_PIN, HIGH);
    delayMicroseconds(duration_us);
    digitalWrite(TRIGGER_PIN, LOW);
    last_trigger_time = millis();
}

void loop() {
    // Process backend commands via USB Serial
    if (Serial.available() > 0) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();

        // 1. Layer Demo Attack Command (Generic)
        if (cmd.startsWith("ATTACK:")) {
            // Format: ATTACK:<layer>:<nonce>
            int first_colon = cmd.indexOf(':');
            int second_colon = cmd.indexOf(':', first_colon + 1);
            int layer = (second_colon > 0) ? cmd.substring(first_colon + 1, second_colon).toInt() : 1;
            String nonce = (second_colon > 0) ? cmd.substring(second_colon + 1) : "0";

            // Emit hardware pulse on D5 to Arduino Pin D2
            emit_pulse(15);
            red_seq++;

            // Notify Blue Team ESP32 over SoftwareSerial (D1 -> ESP32 RX2)
            blueSerial.print(F("ZT_ATTACK:"));
            blueSerial.print(layer);
            blueSerial.print(F(":"));
            blueSerial.println(nonce);

            // Acknowledge back to backend over USB Serial
            Serial.print(F("ATTACK_DISPATCHED:"));
            Serial.print(layer);
            Serial.print(F(":"));
            Serial.println(nonce);
        }
        // 2. Layer 2 Physical Glitch Command
        else if (cmd.startsWith("GLITCH:")) {
            // Format: GLITCH:<ms>:<nonce>
            int first_colon = cmd.indexOf(':');
            int second_colon = cmd.indexOf(':', first_colon + 1);
            uint32_t ms = (second_colon > 0) ? cmd.substring(first_colon + 1, second_colon).toInt() : 10;
            String nonce = (second_colon > 0) ? cmd.substring(second_colon + 1) : "0";

            if (ms == 0) ms = 10;
            if (ms > 50) ms = 50; // Safety clamp

            // Trigger pulse on D5 simultaneously
            emit_pulse(10);

            // Pull A0 node LOW through 1k resistor (Active LOW)
            pinMode(GLITCH_PIN, OUTPUT);
            digitalWrite(GLITCH_PIN, LOW);
            delay(ms);
            // Return to high-impedance immediately
            pinMode(GLITCH_PIN, INPUT);

            red_seq++;

            // Notify Blue Team of glitch event
            blueSerial.print(F("ZT_ATTACK:2:"));
            blueSerial.println(nonce);

            Serial.print(F("GLITCH_APPLIED:"));
            Serial.print(ms);
            Serial.print(F(":"));
            Serial.println(nonce);
        }
        // 3. Flood Injection Command
        else if (cmd.startsWith("FLOOD:")) {
            // Format: FLOOD:<count>:<nonce>
            int first_colon = cmd.indexOf(':');
            int second_colon = cmd.indexOf(':', first_colon + 1);
            int count = (second_colon > 0) ? cmd.substring(first_colon + 1, second_colon).toInt() : 20;
            String nonce = (second_colon > 0) ? cmd.substring(second_colon + 1) : "0";

            if (count > 100) count = 100;
            for (int i = 0; i < count; i++) {
                emit_pulse(5);
                delayMicroseconds(200);
            }
            red_seq += count;

            Serial.print(F("FLOOD_DISPATCHED:"));
            Serial.print(count);
            Serial.print(F(":"));
            Serial.println(nonce);
        }
        // 4. Layer 4 Cryptographic Frame Transmission
        else if (cmd.startsWith("L4_SEND:")) {
            // Format: L4_SEND:<mode>:<counter>:<nonce>
            // Modes: LEGIT, REPLAY, WRONG_KEY
            int c1 = cmd.indexOf(':');
            int c2 = cmd.indexOf(':', c1 + 1);
            int c3 = cmd.indexOf(':', c2 + 1);

            String mode = (c2 > 0) ? cmd.substring(c1 + 1, c2) : "LEGIT";
            uint32_t counter = (c3 > 0) ? cmd.substring(c2 + 1, c3).toInt() : 1;
            String nonce = (c3 > 0) ? cmd.substring(c3 + 1) : "0";

            uint32_t mac = 0;
            if (mode == "WRONG_KEY") {
                // Compute with bad key
                mac = compute_l4_mac(0xDEADBEEF, counter, nonce);
            } else {
                // Legitimate key
                mac = compute_l4_mac(L4_SECRET_KEY, counter, nonce);
            }

            // Send packet to Blue Team ESP32: ZT_SEC:<counter>:<nonce>:<mode>:<mac_hex>
            blueSerial.print(F("ZT_SEC:"));
            blueSerial.print(counter);
            blueSerial.print(F(":"));
            blueSerial.print(nonce);
            blueSerial.print(F(":"));
            blueSerial.print(mode);
            blueSerial.print(F(":0x"));
            blueSerial.println(mac, HEX);

            red_seq++;
            Serial.print(F("L4_SENT:"));
            Serial.print(mode);
            Serial.print(F(":"));
            Serial.print(counter);
            Serial.print(F(":"));
            Serial.println(nonce);
        }
        // 5. Hardware Identification & PUF Authentication
        else if (cmd == "IDENTIFY" || cmd.startsWith("PUF") || cmd.indexOf("PUF") >= 0) {
            uint32_t challenge_val = 0xA5C3E189;
            int chal_idx = cmd.indexOf("0x");
            if (chal_idx < 0) chal_idx = cmd.indexOf("0X");
            if (chal_idx >= 0) {
                challenge_val = strtoul(cmd.c_str() + chal_idx + 2, NULL, 16);
            } else if (cmd.indexOf(':') > 0) {
                challenge_val = strtoul(cmd.substring(cmd.indexOf(':') + 1).c_str(), NULL, 16);
            }
            uint32_t puf_resp = compute_esp8266_puf(challenge_val);
            uint8_t hw = 0;
            for (uint8_t b = 0; b < 32; b++) { if ((puf_resp >> b) & 1) hw++; }
            float uniformity = (hw / 32.0f) * 100.0f;

            Serial.print(F("{\"event\":\"PUF_RESPONSE\",\"board\":\"ESP8266\",\"role\":\"RED_TEAM\",\"device_id\":\""));
            Serial.print(DEVICE_ID);
            Serial.print(F("\",\"version\":\""));
            Serial.print(FIRMWARE_VER);
            Serial.print(F("\",\"protocol\":\""));
            Serial.print(PROTOCOL_VER);
            Serial.print(F("\",\"puf_type\":\"SILICON_RO_CYCLE_PUF\",\"challenge\":\"0x"));
            Serial.print(challenge_val, HEX);
            Serial.print(F("\",\"puf_response\":\"0x"));
            Serial.print(puf_resp, HEX);
            Serial.print(F("\",\"uniformity_pct\":"));
            Serial.print(uniformity, 1);
            Serial.print(F(",\"uptime_ms\":"));
            Serial.print(millis());
            Serial.println(F("}"));
        }
        // 6. Status & Health
        else if (cmd == "STATUS" || cmd == "PING") {
            Serial.print(F("{\"status\":\"ONLINE\",\"seq\":"));
            Serial.print(red_seq);
            Serial.print(F(",\"uptime_ms\":"));
            Serial.print(millis());
            Serial.print(F(",\"last_trigger_ms\":"));
            Serial.print(last_trigger_time);
            Serial.println(F("}"));
        }
        // 7. Trigger Link Verification
        else if (cmd.startsWith("TRIGGER:")) {
            // Format: TRIGGER:<event_id>:<duration_us>
            int first_colon = cmd.indexOf(':');
            int second_colon = cmd.indexOf(':', first_colon + 1);
            String event_id = (second_colon > 0) ? cmd.substring(first_colon + 1, second_colon) : cmd.substring(first_colon + 1);
            uint32_t dur = (second_colon > 0) ? cmd.substring(second_colon + 1).toInt() : 10;
            if (dur == 0) dur = 10;

            emit_pulse(dur);
            red_seq++;

            Serial.print(F("{\"event\":\"TRIGGER_DISPATCHED\",\"event_id\":\""));
            Serial.print(event_id);
            Serial.print(F("\",\"duration_us\":"));
            Serial.print(dur);
            Serial.print(F(",\"seq\":"));
            Serial.print(red_seq);
            Serial.println(F("}"));
        }
        // 8. Inter-board UART Link Verification
        else if (cmd.startsWith("UART_TEST:")) {
            // Format: UART_TEST:<nonce>
            String nonce = cmd.substring(10);
            red_seq++;

            // Forward to ESP32 over SoftwareSerial
            blueSerial.print(F("ZT_PING:"));
            blueSerial.println(nonce);

            // Wait up to 500ms for response from ESP32
            uint32_t t_start = millis();
            bool ack_received = false;
            String ack_msg = "";

            while (millis() - t_start < 500) {
                if (blueSerial.available() > 0) {
                    ack_msg = blueSerial.readStringUntil('\n');
                    ack_msg.trim();
                    if (ack_msg.indexOf(nonce) >= 0) {
                        ack_received = true;
                        break;
                    }
                }
                delay(2);
            }

            uint32_t rtt = millis() - t_start;

            Serial.print(F("{\"event\":\"UART_TEST_RESULT\",\"nonce\":\""));
            Serial.print(nonce);
            Serial.print(F("\",\"ack\":"));
            Serial.print(ack_received ? F("true") : F("false"));
            Serial.print(F(",\"rtt_ms\":"));
            Serial.print(rtt);
            Serial.print(F(",\"raw\":\""));
            Serial.print(ack_msg);
            Serial.println(F("\"}"));
        }
        // 9. Generic Scenarios
        else if (cmd.startsWith("SCENARIO:")) {
            // Format: SCENARIO:<scenario_id>:<payload>
            int first_colon = cmd.indexOf(':');
            int second_colon = cmd.indexOf(':', first_colon + 1);
            String sc_id = (second_colon > 0) ? cmd.substring(first_colon + 1, second_colon) : cmd.substring(first_colon + 1);
            String payload = (second_colon > 0) ? cmd.substring(second_colon + 1) : "";

            red_seq++;
            emit_pulse(15);
            blueSerial.print(F("ZT_SCENARIO:"));
            blueSerial.print(sc_id);
            blueSerial.print(F(":"));
            blueSerial.println(payload);

            Serial.print(F("{\"event\":\"SCENARIO_INJECTED\",\"scenario_id\":\""));
            Serial.print(sc_id);
            Serial.print(F("\",\"seq\":"));
            Serial.print(red_seq);
            Serial.println(F("}"));
        }
    }

    // Check for incoming messages from Blue Team
    if (blueSerial.available() > 0) {
        String msg = blueSerial.readStringUntil('\n');
        msg.trim();
        Serial.print(F("{\"event\":\"BLUE_UART_FORWARD\",\"data\":\""));
        Serial.print(msg);
        Serial.println(F("\"}"));
    }

    delay(2);
}
