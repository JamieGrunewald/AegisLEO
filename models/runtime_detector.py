"""
AegisLEO Runtime Detector

Created by: Jamie Grunewald
Date: 2026-03-23
Version: v0.1.0

Purpose
-------
Provide a lightweight runtime anomaly-detection interface for live telemetry.

Why this file exists
--------------------
This module is designed to sit in the ground-station receive path after:
- signature verification
- AES-GCM decryption
- frame parsing
- replay protection

For now, it uses a simple rule-based scoring method as a placeholder.
Later, this same interface can be backed by an autoencoder or another ML model
without changing the receiver's call pattern.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DetectionResult:
    """
    Result of runtime anomaly evaluation.
    """

    is_anomalous: bool
    score: float
    threshold: float
    reasons: list[str]


def extract_features(frame: dict[str, Any]) -> dict[str, float]:
    """
    Extract a small numeric feature set from a parsed telemetry frame.

    Expected payload example
    ------------------------
    {
        "temp_c": 12.3,
        "bus_v": 5.01,
        "bus_i": 0.42,
        "state": "NOMINAL"
    }
    """
    payload = frame.get("payload", {})

    return {
        "temp_c": float(payload.get("temp_c", 0.0)),
        "bus_v": float(payload.get("bus_v", 0.0)),
        "bus_i": float(payload.get("bus_i", 0.0)),
        "sequence": float(frame.get("sequence", 0)),
        "apid": float(frame.get("apid", 0)),
    }


class RuntimeDetector:
    """
    Lightweight runtime detector.

    Current behavior
    ----------------
    Uses a simple rule-based anomaly score as a placeholder:
    - temperature outside expected range
    - bus voltage outside expected range
    - bus current outside expected range
    - non-NOMINAL state

    Later this class can be upgraded to load a trained ML model while keeping
    the same public `detect()` method.
    """

    def __init__(self, threshold: float = 1.0) -> None:
        self.threshold = threshold

    def detect(self, frame: dict[str, Any]) -> DetectionResult:
        """
        Evaluate a telemetry frame and return anomaly result.
        """
        payload = frame.get("payload", {})
        features = extract_features(frame)

        score = 0.0
        reasons: list[str] = []

        temp_c = features["temp_c"]
        if temp_c < -40.0 or temp_c > 85.0:
            score += 1.0
            reasons.append("temperature_out_of_range")

        bus_v = features["bus_v"]
        if bus_v < 4.5 or bus_v > 5.5:
            score += 1.0
            reasons.append("bus_voltage_out_of_range")

        bus_i = features["bus_i"]
        if bus_i < 0.0 or bus_i > 2.0:
            score += 1.0
            reasons.append("bus_current_out_of_range")

        state = str(payload.get("state", "UNKNOWN"))
        if state != "NOMINAL":
            score += 0.5
            reasons.append(f"state_not_nominal:{state}")

        return DetectionResult(
            is_anomalous=score >= self.threshold,
            score=score,
            threshold=self.threshold,
            reasons=reasons,
        )