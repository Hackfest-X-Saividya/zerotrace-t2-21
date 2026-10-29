"""
ZeroTrace — Bounded Circular Ring Buffer for High-Rate Time-Series Telemetry
Thread-safe, pre-allocated numpy arrays for high-rate ingestion without memory leaks.
"""

import threading
import numpy as np
from typing import Dict, Any, List, Optional
from backend.config import MAX_WAVEFORM_SAMPLES

class WaveformRingBuffer:
    def __init__(self, capacity: int = MAX_WAVEFORM_SAMPLES):
        self.capacity = capacity
        self.lock = threading.Lock()
        
        # Pre-allocated arrays
        self.time_ms = np.zeros(capacity, dtype=np.float64)
        self.voltage = np.zeros(capacity, dtype=np.float32)
        self.trigger = np.zeros(capacity, dtype=np.int8)
        
        self.head = 0
        self.count = 0
        self.total_appended = 0

    def append(self, t_ms: float, v: float, trig: int):
        with self.lock:
            self.time_ms[self.head] = t_ms
            self.voltage[self.head] = v
            self.trigger[self.head] = trig
            
            self.head = (self.head + 1) % self.capacity
            if self.count < self.capacity:
                self.count += 1
            self.total_appended += 1

    def append_batch(self, times_ms: np.ndarray, volts: np.ndarray, trigs: np.ndarray):
        with self.lock:
            n = len(times_ms)
            for i in range(n):
                self.time_ms[self.head] = times_ms[i]
                self.voltage[self.head] = volts[i]
                self.trigger[self.head] = trigs[i]
                self.head = (self.head + 1) % self.capacity
                if self.count < self.capacity:
                    self.count += 1
                self.total_appended += 1

    def get_window(self, duration_ms: float = 200.0, max_points: int = 1500) -> Dict[str, Any]:
        """Returns the most recent rolling window of data, decimated for smooth UI rendering."""
        with self.lock:
            if self.count == 0:
                return {"time_ms": [], "voltage": [], "trigger": [], "sample_count": 0}

            # Extract ordered contiguous samples
            if self.count < self.capacity:
                t_arr = self.time_ms[:self.count]
                v_arr = self.voltage[:self.count]
                trig_arr = self.trigger[:self.count]
            else:
                t_arr = np.concatenate((self.time_ms[self.head:], self.time_ms[:self.head]))
                v_arr = np.concatenate((self.voltage[self.head:], self.voltage[:self.head]))
                trig_arr = np.concatenate((self.trigger[self.head:], self.trigger[:self.head]))

            # Slice to window duration
            latest_t = t_arr[-1]
            cutoff_t = latest_t - duration_ms
            idx = np.searchsorted(t_arr, cutoff_t)
            
            t_win = t_arr[idx:]
            v_win = v_arr[idx:]
            trig_win = trig_arr[idx:]

            # Decimate if point count exceeds max_points for UI performance
            total_win_pts = len(t_win)
            if total_win_pts > max_points:
                step = int(np.ceil(total_win_pts / max_points))
                t_win = t_win[::step]
                v_win = v_win[::step]
                trig_win = trig_win[::step]

            return {
                "time_ms": t_win.tolist(),
                "voltage": np.round(v_win, 3).tolist(),
                "trigger": trig_win.tolist(),
                "sample_count": total_win_pts,
                "latest_t_ms": round(float(latest_t), 2)
            }

    def clear(self):
        with self.lock:
            self.head = 0
            self.count = 0
            self.total_appended = 0

