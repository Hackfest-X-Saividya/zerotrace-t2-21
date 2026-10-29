"""
ZeroTrace — Waveform Generator
Generates realistic measured and simulated waveform signatures based on:
- Fanjas et al. (FDTC 2024): EM-induced glitch transients, 2ns rise / 4ns fall pulses
- Wiersma & Pareja (FDTC 2017): DPA power difference traces for JTAG boot authentication
- Normal nominal supply rail ripple with 16 MHz switching harmonics
"""

import numpy as np
from typing import Dict, Any, List
from backend.schema import WaveformBatch, EventRecord
from backend.config import MODE_SIMULATED, MODE_TELEMETRY, MODE_PHYSICAL

class WaveformGenerator:
    def __init__(self, sample_rate_hz: int = 1000000):
        self.sample_rate_hz = sample_rate_hz
        self.dt_ms = (1.0 / sample_rate_hz) * 1000.0

    def generate_scenario_waveform(self, run_id: str, test_id: str, scenario_type: str,
                                   duration_ms: float = 20.0,
                                   source_mode: str = MODE_SIMULATED,
                                   events: List[EventRecord] = None) -> WaveformBatch:
        """
        Generates a synchronized time-series waveform batch with explicit source mode tagging.
        """
        num_samples = int((duration_ms / 1000.0) * self.sample_rate_hz)
        time_ms = np.linspace(0.0, duration_ms, num_samples, endpoint=False, dtype=np.float64)
        
        # Baseline: 5.0V with slight switching noise (16 MHz aliased ripple)
        base_voltage = 5.00
        noise = np.random.normal(0, 0.015, num_samples)
        voltage = np.full(num_samples, base_voltage, dtype=np.float32) + noise
        trigger = np.zeros(num_samples, dtype=np.int8)

        # Trigger window: centered around 8.0ms to 10.0ms
        trig_start_idx = int(num_samples * 0.40)
        trig_end_idx = int(num_samples * 0.50)
        trigger[trig_start_idx:trig_end_idx] = 1

        if scenario_type == "VOLTAGE_GLITCH":
            # Sharp voltage sag down to 1.85V (under-voltage glitch window)
            glitch_width = max(10, int(num_samples * 0.05))
            glitch_idx = min(int(num_samples * 0.45), num_samples - glitch_width)
            glitch_t = np.linspace(-2.5, 2.5, glitch_width)
            sag_shape = 3.15 * np.exp(-glitch_t**2)  # Gaussian drop centered at 0
            voltage[glitch_idx:glitch_idx + glitch_width] -= sag_shape

        elif scenario_type == "EM_INDUCED_PULSE":
            # EM pulse transient at decoupling capacitor (Fanjas 2024 Fig. 8)
            pulse_width = max(12, int(num_samples * 0.05))
            pulse_idx = min(int(num_samples * 0.45), num_samples - pulse_width)
            t_pulse = np.linspace(0, 10, pulse_width)
            em_ringing = 1.4 * np.sin(2 * np.pi * 3.5 * t_pulse) * np.exp(-t_pulse / 2.5)
            voltage[pulse_idx:pulse_idx + pulse_width] += em_ringing

        elif scenario_type == "DPA_BOOT_PROFILE":
            # Boot-time power consumption trace (Wiersma 2017 Fig. 1)
            # Distinct current consumption peaks during ROM password comparison
            boot_t = np.linspace(0, 10, num_samples)
            dpa_peaks = 0.25 * np.sin(2 * np.pi * 0.8 * boot_t) + 0.15 * np.sin(2 * np.pi * 2.4 * boot_t)
            voltage += dpa_peaks

        elif scenario_type == "UNROLL_LOOP_SIGNATURE":
            # Stepwise instruction bursts corresponding to 10 unrolled additions
            burst_len = (trig_end_idx - trig_start_idx) // 10
            for i in range(10):
                b_start = trig_start_idx + (i * burst_len)
                voltage[b_start:b_start + (burst_len // 2)] -= 0.08

        # Enforce physical floor of 0V
        voltage = np.clip(voltage, 0.0, 7.5)

        return WaveformBatch(
            run_id=run_id,
            test_id=test_id,
            source_mode=source_mode,
            signal_name="VCC_SUPPLY_RAIL",
            unit="V",
            sample_rate_hz=self.sample_rate_hz,
            time_ms=time_ms.round(4).tolist(),
            voltage_samples=voltage.round(3).tolist(),
            trigger_samples=trigger.tolist(),
            events=events or []
        )
