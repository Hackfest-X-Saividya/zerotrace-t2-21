/*
 * ZeroTrace — Target Microcontroller Firmware (Arduino Uno / ATmega328P)
 * Implements Layer 2 Defensive Controls:
 * - Dual-counter unrolled execution loop (Fanjas et al., FDTC 2024, Algorithm 1)
 * - Complementary conditional branch authentication (Wiersma & Pareja, FDTC 2017, Listing 2)
 * - ADC Rail Telemetry, Register Invariant Verification, and Trigger Signaling
 */

#include <stdint.h>
#include <avr/wdt.h>

#define TRIGGER_PIN 2       // Fast trigger pulse for acquisition synchronization
#define RAIL_ADC_PIN A0     // Target supply rail ADC monitoring pin
#define LED_INDICATOR 13    // Status LED

static uint32_t message_seq = 0;
static volatile uint8_t auth_flag = 0xAA;
static volatile uint8_t auth_flag_inv = ~0xAA;

// CRC-16 for frame integrity
uint16_t compute_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i];
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc = crc >> 1;
            }
        }
    }
    return crc;
}

void setup() {
    pinMode(TRIGGER_PIN, OUTPUT);
    digitalWrite(TRIGGER_PIN, LOW);
    pinMode(LED_INDICATOR, OUTPUT);
    digitalWrite(LED_INDICATOR, LOW);

    Serial.begin(115200);
    while (!Serial) { ; }

    // Enable hardware watchdog (2 seconds)
    wdt_enable(WDTO_2S);

    Serial.println(F("{\"event\":\"TARGET_BOOT\",\"target\":\"ATmega328P\",\"status\":\"READY\"}"));
}

/*
 * Layer 2 / Problem 2: Unroll loop with dual-counter fault detection
 * Evaluates whether an instruction-skip fault (F1-F4) corrupted counter or arithmetic logic.
 */
bool run_unroll_scenario(uint8_t iterations, uint16_t *final_w10) {
    wdt_reset();
    
    // Assert trigger high before critical block
    digitalWrite(TRIGGER_PIN, HIGH);

    volatile uint16_t w0 = iterations;
    volatile uint16_t w1 = iterations;
    volatile uint16_t w2 = 100, w3 = 99, w4 = 98, w5 = 97, w6 = 96;
    volatile uint16_t w10 = 0x0000;

    // Critical arithmetic unroll sequence
    while (w0 > 0) {
        w5 = w6 - 1;
        w4 = w5 - 1;
        w3 = w4 - 1;
        w2 = w3 - 1;
        w6 = w2 - 1;
        w1 = w1 - 1;
        w0 = w0 - 1;

        // Invariant assertion: w0 must strictly equal w1
        if (w0 != w1) {
            w10 = 0x5555; // Flagged fault condition (Fanjas 2024 Table I)
            break;
        }
    }

    // Trigger low immediately after critical block
    digitalWrite(TRIGGER_PIN, LOW);

    *final_w10 = w10;
    return (w10 == 0x0000 && w0 == 0 && w1 == 0);
}

/*
 * Layer 2 / Problem 3: Complementary conditional branch authentication check
 * Defeats single-glitch branch bypass attacks (Wiersma 2017 Listing 2)
 */
bool run_auth_scenario(uint8_t request_code) {
    wdt_reset();
    digitalWrite(TRIGGER_PIN, HIGH);

    // Complementary dual-check logic
    bool grant_access = false;
    if (auth_flag == request_code) {
        // Redundant inverse verification
        if (auth_flag_inv == (uint8_t)(~request_code)) {
            grant_access = true;
        }
    }

    digitalWrite(TRIGGER_PIN, LOW);
    return grant_access;
}

void loop() {
    wdt_reset();

    // Read analog rail sample
    int adc_val = analogRead(RAIL_ADC_PIN);
    float rail_volts = (adc_val * 5.0f) / 1023.0f;

    // Check for incoming commands from Red Team / Backend
    if (Serial.available() > 0) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();

        if (cmd.startsWith("UNROLL")) {
            uint16_t w10 = 0;
            bool ok = run_unroll_scenario(10, &w10);
            Serial.print(F("{\"seq\":"));
            Serial.print(++message_seq);
            Serial.print(F(",\"event\":\"UNROLL_RESULT\",\"pass\":"));
            Serial.print(ok ? F("true") : F("false"));
            Serial.print(F(",\"w10\":\"0x"));
            Serial.print(w10, HEX);
            Serial.print(F("\",\"rail_v\":"));
            Serial.print(rail_volts, 2);
            Serial.println(F("}"));
        } else if (cmd.startsWith("AUTH:")) {
            uint8_t req = cmd.substring(5).toInt();
            bool granted = run_auth_scenario(req);
            Serial.print(F("{\"seq\":"));
            Serial.print(++message_seq);
            Serial.print(F(",\"event\":\"AUTH_RESULT\",\"granted\":"));
            Serial.print(granted ? F("true") : F("false"));
            Serial.print(F(",\"rail_v\":"));
            Serial.print(rail_volts, 2);
            Serial.println(F("}"));
        } else if (cmd.equals("PING")) {
            Serial.print(F("{\"seq\":"));
            Serial.print(++message_seq);
            Serial.print(F(",\"event\":\"PONG\",\"rail_v\":"));
            Serial.print(rail_volts, 2);
            Serial.println(F("}"));
        }
    }

    delay(20);
}

