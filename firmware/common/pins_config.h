/**
 * ZeroTrace - Common Pin Configuration & Chip Hardware Inspection
 * ---------------------------------------------------------------
 * Shared between Baseline and Hardened ESP32 targets.
 * Handles automatic PSRAM conflict detection (ESP32-WROVER chips
 * dedicate GPIO 16 and 17 to PSRAM, so alternative pins are selected).
 */

#ifndef ZEROTRACE_PINS_CONFIG_H
#define ZEROTRACE_PINS_CONFIG_H

#include <Arduino.h>
#include "esp_system.h"
#include "esp_chip_info.h"

// Default UART Pins for Secondary Serial (ESP32-WROOM standard)
#define DEFAULT_UART2_RX_PIN 16
#define DEFAULT_UART2_TX_PIN 17

// Alternative UART Pins if PSRAM is detected (e.g., ESP32-WROVER)
#define ALT_UART2_RX_PIN     22
#define ALT_UART2_TX_PIN     21

// Status LED Pin
#define STATUS_LED_PIN       2

// Hardware Pulse Input/Output Pin (Simulated Fault Pulse)
#define SIM_FAULT_PULSE_PIN  25

// Structure holding inspected chip hardware metadata
struct ChipHardwareInfo {
    const char* model;
    uint32_t revision;
    uint32_t cpu_freq_mhz;
    uint32_t flash_size_bytes;
    uint32_t psram_size_bytes;
    bool has_psram;
    uint8_t uart2_rx;
    uint8_t uart2_tx;
};

inline ChipHardwareInfo inspect_chip_hardware() {
    ChipHardwareInfo info;
    info.model = ESP.getChipModel();
    info.revision = ESP.getChipRevision();
    info.cpu_freq_mhz = ESP.getCpuFreqMHz();
    info.flash_size_bytes = ESP.getFlashChipSize();
    info.psram_size_bytes = ESP.getPsramSize();
    info.has_psram = (info.psram_size_bytes > 0);

    // If PSRAM is present, avoid GPIO 16/17 to prevent bus collisions
    if (info.has_psram) {
        info.uart2_rx = ALT_UART2_RX_PIN;
        info.uart2_tx = ALT_UART2_TX_PIN;
    } else {
        info.uart2_rx = DEFAULT_UART2_RX_PIN;
        info.uart2_tx = DEFAULT_UART2_TX_PIN;
    }

    return info;
}

#endif // ZEROTRACE_PINS_CONFIG_H
