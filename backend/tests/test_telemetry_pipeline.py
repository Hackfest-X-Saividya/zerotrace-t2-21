"""
Tests for Waveform Ring Buffer, Decimation, and Waveform Generation Pipeline
"""

import numpy as np
from backend.telemetry.ring_buffer import WaveformRingBuffer
from backend.telemetry.waveform_generator import WaveformGenerator
from backend.config import MODE_SIMULATED, MODE_TELEMETRY

def test_ring_buffer_bounded_capacity():
    buf = WaveformRingBuffer(capacity=100)
    for i in range(250):
        buf.append(float(i), 5.0, 0)
    assert buf.count == 100
    assert buf.total_appended == 250

def test_ring_buffer_window_and_decimation():
    buf = WaveformRingBuffer(capacity=5000)
    for i in range(2000):
        buf.append(float(i), 5.0 + (i % 5) * 0.01, 1 if i % 100 == 0 else 0)
    
    # Request 500ms window decimated to 500 points
    win = buf.get_window(duration_ms=500.0, max_points=500)
    assert len(win["time_ms"]) <= 500
    assert len(win["voltage"]) == len(win["time_ms"])
    assert len(win["trigger"]) == len(win["time_ms"])

def test_waveform_generator_provenance():
    gen = WaveformGenerator(sample_rate_hz=10000)
    batch = gen.generate_scenario_waveform("RUN_TEST", "T_GLITCH", "VOLTAGE_GLITCH", duration_ms=10.0, source_mode=MODE_SIMULATED)
    assert batch.source_mode == MODE_SIMULATED
    assert len(batch.time_ms) == 100
    assert min(batch.voltage_samples) < 3.0  # Glitch dip present

