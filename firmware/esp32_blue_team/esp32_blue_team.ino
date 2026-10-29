/*
 * ZeroTrace — ESP32 #2 Blue Team Monitor Firmware
 * Monitors target bus, detects anomalies, enforces quarantine/reset containment,
 * and reports structured defensive evidence to the Backend.
 */

#include <Arduino.h>

#define TARGET_RESET_PIN 19 // Connected to Target reset line for emergency containment
#define MONITOR_SERIAL Serial2

static uint32_t blue_seq = 0;
static uint32_t last_target_heartbeat = 0;
static bool target_healthy = true;

void setup() {
    Serial.begin(115200);
    MONITOR_SERIAL.begin(115200, SERIAL_8N1, 22, 23); // Monitor bus on RX=22, TX=23
    pinMode(TARGET_RESET_PIN, OUTPUT);
    digitalWrite(TARGET_RESET_PIN, HIGH); // Inactive reset (HIGH for active-low reset)

    delay(500);
    Serial.println(F("{\"role\":\"BLUE_TEAM\",\"device\":\"ESP32_2\",\"status\":\"ONLINE\"}"));
}

void enforce_containment(const String &reason) {
    blue_seq++;
    uint32_t t0 = micros();

    // Pull reset low for 10ms to trigger clean microcontroller reboot
    digitalWrite(TARGET_RESET_PIN, LOW);
    delay(10);
    digitalWrite(TARGET_RESET_PIN, HIGH);

    uint32_t latency_us = micros() - t0;

    Serial.print(F("{\"seq\":"));
    Serial.print(blue_seq);
    Serial.print(F(",\"role\":\"BLUE_TEAM\",\"event\":\"CONTAINMENT_ENFORCED\",\"reason\":\""));
    Serial.print(reason);
    Serial.print(F("\",\"containment_latency_us\":"));
    Serial.print(latency_us);
    Serial.println(F("}"));
}

void loop() {
    // Monitor incoming target traffic
    if (MONITOR_SERIAL.available()) {
        String msg = MONITOR_SERIAL.readStringUntil('\n');
        msg.trim();
        last_target_heartbeat = millis();

        if (msg.indexOf("\"w10\":\"0x5555\"") >= 0) {
            // Fault detected! Counter mismatch
            enforce_containment("FAULT_F2_COUNTER_CORRUPTION");
        } else if (msg.indexOf("\"granted\":true") >= 0 && msg.indexOf("\"unauthorized\"") >= 0) {
            // Unauthorized bypass detected
            enforce_containment("AUTH_BRANCH_BYPASS_DETECTED");
        } else {
            // Forward validated telemetry
            Serial.print(F("{\"role\":\"BLUE_TEAM\",\"event\":\"OBSERVATION\",\"raw\":"));
            Serial.print(msg);
            Serial.println(F("}"));
        }
    }

    // Check for target freeze (hang / unhandled crash)
    if (millis() - last_target_heartbeat > 3000 && target_healthy) {
        // Heartbeat timeout
        target_healthy = false;
        Serial.println(F("{\"role\":\"BLUE_TEAM\",\"event\":\"HEARTBEAT_TIMEOUT\",\"risk\":\"HIGH\"}"));
    }

    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        if (cmd.equals("RESET_TARGET")) {
            enforce_containment("MANUAL_OPERATOR_REQUEST");
        } else if (cmd.equals("STATUS")) {
            Serial.print(F("{\"role\":\"BLUE_TEAM\",\"status\":\"READY\",\"seq\":"));
            Serial.print(blue_seq);
            Serial.println(F("}"));
        }
    }

    delay(10);
}

