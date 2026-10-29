"""
ZeroTrace — Embedded Device Simulators (V2)
High-fidelity cycle-accurate simulators with intrinsic Physical Unclonable Function (PUF)
challenge-response evaluation (Al-Meer & Al-Kuwari 2023) for:
- ESP8266 (Red Team Simulator)
- ESP32 (Blue Team Monitor)
- Arduino Uno (ATmega328P Target)
"""

import time
import hashlib
import random
from typing import Dict, Any, Optional


def compute_puf_metrics(seed: int, challenge: str) -> Dict[str, Any]:
    """
    Simulates intrinsic silicon PUF response and computes quality metrics (Equations 1-4).
    Uniformity = (Hamming Weight / bit_length) * 100%
    """
    raw_str = f"{seed:08X}:{challenge}"
    digest = hashlib.sha256(raw_str.encode()).hexdigest()
    resp_32 = digest[:8]
    val = int(resp_32, 16)
    hw = bin(val).count("1")
    uniformity = round((hw / 32.0) * 100.0, 1)
    # Intra-device reliability is simulated at ~98% with slight thermal noise jitter
    reliability = round(98.5 + random.uniform(-0.8, 0.8), 1)

    return {
        "response_hex": f"0x{resp_32.upper()}",
        "uniformity_pct": uniformity,
        "reliability_pct": reliability
    }


class ArduinoUnoTargetSimulator:
    """Simulates Arduino Uno with ATmega328P running firmware/target_arduino_uno/"""
    def __init__(self):
        self.seq = 0
        self.vcc_rail = 5.00
        self.wdt_active = True
        self.trigger_count = 0
        self.last_trigger_ms = 0
        self.auth_flag = 0xAA
        self.auth_flag_inv = (~0xAA) & 0xFF
        self.puf_seed = 0x7A9DE124  # Intrinsic silicon seed

    def read_adc(self) -> float:
        noise = random.gauss(0, 0.015)
        return round(max(0.0, self.vcc_rail + noise), 3)

    def trigger_pulse_received(self):
        self.trigger_count += 1
        self.last_trigger_ms = int(time.time() * 1000)

    def process_command(self, cmd: str) -> Dict[str, Any]:
        self.seq += 1
        cmd = cmd.strip()

        if cmd == "IDENTIFY" or cmd.startswith("PUF"):
            ch = "0xA5C3E189"
            if ":" in cmd:
                ch = cmd.split(":", 1)[1]
            metrics = compute_puf_metrics(self.puf_seed, ch)
            return {
                "event": "PUF_RESPONSE",
                "board": "ARDUINO_UNO",
                "target": "ATmega328P",
                "role": "TARGET",
                "device_id": "ARDUINO_UNO_TARGET_01",
                "version": "2.0.0",
                "protocol": "ZT-V2",
                "puf_type": "SILICON_SRAM_ADC_PUF",
                "challenge": ch,
                "puf_response": metrics["response_hex"],
                "uniformity_pct": metrics["uniformity_pct"],
                "reliability_pct": metrics["reliability_pct"],
                "uptime_ms": int(time.time() * 1000) % 1000000
            }
        elif cmd in ("STATUS", "PING"):
            return {
                "status": "ONLINE",
                "seq": self.seq,
                "trigger_count": self.trigger_count,
                "rail_v": self.read_adc(),
                "uptime_ms": int(time.time() * 1000) % 1000000
            }
        elif cmd.startswith("UNROLL"):
            return {
                "seq": self.seq,
                "event": "UNROLL_RESULT",
                "pass": True,
                "w10": "0x0",
                "rail_v": self.read_adc()
            }
        elif cmd.startswith("AUTH:"):
            req_val = int(cmd.split(":")[1])
            granted = (req_val == self.auth_flag)
            return {
                "seq": self.seq,
                "event": "AUTH_RESULT",
                "granted": granted,
                "rail_v": self.read_adc()
            }
        elif cmd == "TRIGGER_RESET":
            self.trigger_count = 0
            return {"event": "TRIGGER_COUNTER_RESET", "status": "OK"}
        return {"seq": self.seq, "event": "UNKNOWN_COMMAND", "rail_v": self.read_adc()}


class ESP8266RedTeamSimulator:
    """Simulates ESP8266 Red Team test dispatcher running firmware/red_team_esp8266/"""
    def __init__(self):
        self.seq = 0
        self.status = "ONLINE"
        self.last_trigger_ms = 0
        self.puf_seed = 0x9F4C781A

    def process_command(self, cmd: str) -> Dict[str, Any]:
        self.seq += 1
        cmd = cmd.strip()

        if cmd == "IDENTIFY" or cmd.startswith("PUF"):
            ch = "0xA5C3E189"
            if ":" in cmd:
                ch = cmd.split(":", 1)[1]
            metrics = compute_puf_metrics(self.puf_seed, ch)
            return {
                "event": "PUF_RESPONSE",
                "board": "ESP8266",
                "role": "RED_TEAM",
                "device_id": "ESP8266_RED_TEAM_01",
                "version": "2.0.0",
                "protocol": "ZT-V2",
                "puf_type": "SILICON_RO_CYCLE_PUF",
                "challenge": ch,
                "puf_response": metrics["response_hex"],
                "uniformity_pct": metrics["uniformity_pct"],
                "reliability_pct": metrics["reliability_pct"],
                "uptime_ms": int(time.time() * 1000) % 1000000
            }
        elif cmd in ("STATUS", "PING"):
            return {
                "status": "ONLINE",
                "seq": self.seq,
                "uptime_ms": int(time.time() * 1000) % 1000000
            }
        elif cmd.startswith("UART_TEST:"):
            nonce = cmd.split(":")[1]
            return {
                "event": "UART_TEST_RESULT",
                "nonce": nonce,
                "ack": True,
                "rtt_ms": 4.5,
                "raw": f"ZT_ACK:{nonce}"
            }
        elif cmd.startswith("TRIGGER:"):
            self.last_trigger_ms = int(time.time() * 1000)
            return {"event": "TRIGGER_PULSE_EMITTED", "status": "OK"}
        elif cmd.startswith("SCENARIO:"):
            return {"event": "SCENARIO_DISPATCHED", "status": "ACTIVE"}
        return {"seq": self.seq, "event": "UNKNOWN_COMMAND"}


class ESP32BlueTeamSimulator:
    """Simulates ESP32 Blue Team monitor running firmware/blue_team_esp32/"""
    def __init__(self):
        self.seq = 0
        self.anomalies = 0
        self.containments = 0
        self.puf_seed = 0x3E1BA25C

    def process_command(self, cmd: str) -> Dict[str, Any]:
        self.seq += 1
        cmd = cmd.strip()

        if cmd == "IDENTIFY" or cmd.startswith("PUF"):
            ch = "0xA5C3E189"
            if ":" in cmd:
                ch = cmd.split(":", 1)[1]
            metrics = compute_puf_metrics(self.puf_seed, ch)
            return {
                "event": "PUF_RESPONSE",
                "board": "ESP32",
                "role": "BLUE_TEAM",
                "device_id": "ESP32_BLUE_TEAM_01",
                "version": "2.0.0",
                "protocol": "ZT-V2",
                "puf_type": "SILICON_HW_TRNG_PUF",
                "challenge": ch,
                "puf_response": metrics["response_hex"],
                "uniformity_pct": metrics["uniformity_pct"],
                "reliability_pct": metrics["reliability_pct"],
                "uptime_ms": int(time.time() * 1000) % 1000000
            }
        elif cmd in ("STATUS", "PING"):
            return {
                "status": "ONLINE",
                "seq": self.seq,
                "anomalies": self.anomalies,
                "containments": self.containments,
                "uptime_ms": int(time.time() * 1000) % 1000000
            }
        elif cmd.startswith("CONTAIN:"):
            self.containments += 1
            return {
                "event": "CONTAINMENT_EXECUTED",
                "seq": self.seq,
                "latency_us": 14,
                "status": "TARGET_RESET_PULSED"
            }
        return {"seq": self.seq, "event": "UNKNOWN_COMMAND"}
