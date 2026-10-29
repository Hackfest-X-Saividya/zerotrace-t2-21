/*
 * ZeroTrace — ESP32 #1 Red Team Simulator Firmware
 * Dispatches controlled, non-destructive test scenarios across 4 layers.
 * Provides precision timing pulses, sequence numbering, and serial logging.
 */

#include <Arduino.h>

#define TRIGGER_OUT_PIN 18  // Fast trigger output to Target / Oscilloscope
#define TARGET_SERIAL Serial2

static uint32_t red_seq = 0;

void setup() {
    Serial.begin(115200);
    TARGET_SERIAL.begin(115200, SERIAL_8N1, 16, 17); // RX=16, TX=17 to Arduino Target
    pinMode(TRIGGER_OUT_PIN, OUTPUT);
    digitalWrite(TRIGGER_OUT_PIN, LOW);

    delay(500);
    Serial.println(F("{\"role\":\"RED_TEAM\",\"device\":\"ESP32_1\",\"status\":\"ONLINE\"}"));
}

void dispatch_scenario(const String &scenario_id, const String &payload) {
    red_seq++;
    uint32_t t_start_us = micros();

    // Pulse trigger for physical instrumentation
    digitalWrite(TRIGGER_OUT_PIN, HIGH);
    delayMicroseconds(5);
    digitalWrite(TRIGGER_OUT_PIN, LOW);

    // Send payload to target serial
    TARGET_SERIAL.println(payload);

    uint32_t elapsed_us = micros() - t_start_us;

    Serial.print(F("{\"seq\":"));
    Serial.print(red_seq);
    Serial.print(F(",\"role\":\"RED_TEAM\",\"event\":\"SCENARIO_DISPATCHED\",\"scenario_id\":\""));
    Serial.print(scenario_id);
    Serial.print(F("\",\"elapsed_us\":"));
    Serial.print(elapsed_us);
    Serial.println(F("}"));
}

void loop() {
    if (Serial.available()) {
        String command = Serial.readStringUntil('\n');
        command.trim();

        if (command.startsWith("TRIGGER:")) {
            int colon = command.indexOf(':', 8);
            String sc_id = command.substring(8, colon);
            String payload = command.substring(colon + 1);
            dispatch_scenario(sc_id, payload);
        } else if (command.equals("STATUS")) {
            Serial.print(F("{\"role\":\"RED_TEAM\",\"status\":\"READY\",\"seq\":"));
            Serial.print(red_seq);
            Serial.println(F("}"));
        }
    }

    // Forward any target responses to backend
    if (TARGET_SERIAL.available()) {
        String target_resp = TARGET_SERIAL.readStringUntil('\n');
        Serial.print(F("{\"role\":\"TARGET_ECHO\",\"data\":"));
        Serial.print(target_resp);
        Serial.println(F("}"));
    }

    delay(10);
}

