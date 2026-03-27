# common/telemetry.py

"""
Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.02.0

Enhancements:
- Stable ML feature ordering
- Mode encoded safely
- Added anomaly mutation helpers
- Added envelope validation hooks (for demo + ML explainability)
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json
import time
from typing import Any, Dict, List


# ---------------------------------------------------------------------
# Mode encoding (stable + extensible)
# ---------------------------------------------------------------------

MODE_MAP = {
    "NOMINAL": 0,
    "SUNPOINT": 1,
    "TX_WINDOW": 2,
}

MODE_COUNT = len(MODE_MAP)


# ---------------------------------------------------------------------
# Telemetry Object
# ---------------------------------------------------------------------

@dataclass
class Telemetry:
    seq: int
    timestamp: float
    temperature_c: float
    battery_pct: int
    mode: str
    latitude: float
    longitude: float
    altitude_km: float
    bus_v: float
    bus_i: float

    # ---------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), separators=(",", ":")).encode("utf-8")

    @staticmethod
    def from_json_bytes(data: bytes) -> "Telemetry":
        obj = json.loads(data.decode("utf-8"))
        return Telemetry(**obj)

    # ---------------------------------------------------------
    # Human-readable output (stage view)
    # ---------------------------------------------------------

    def summary(self) -> str:
        return (
            f"seq={self.seq} "
            f"mode={self.mode} "
            f"temp={self.temperature_c:.1f}C "
            f"battery={self.battery_pct}% "
            f"bus={self.bus_v:.2f}V/{self.bus_i:.3f}A "
            f"lat={self.latitude:.3f} "
            f"lon={self.longitude:.3f} "
            f"alt={self.altitude_km:.1f}km"
        )

    def operator_lines(self) -> list[tuple[str, str]]:
        return [
            ("Sequence", str(self.seq)),
            ("Timestamp", f"{self.timestamp:.3f}"),
            ("Mode", self.mode),
            ("Temperature", f"{self.temperature_c:.1f} C"),
            ("Battery", f"{self.battery_pct}%"),
            ("Bus", f"{self.bus_v:.2f} V / {self.bus_i:.3f} A"),
            ("Latitude", f"{self.latitude:.3f}"),
            ("Longitude", f"{self.longitude:.3f}"),
            ("Altitude", f"{self.altitude_km:.1f} km"),
        ]

    # ---------------------------------------------------------
    # ML Feature Extraction (ordered + stable)
    # ---------------------------------------------------------

    def to_feature_vector(self) -> List[float]:
        """
        Stable feature vector for ML model input.

        IMPORTANT:
        Order must NEVER change once model is trained.
        """

        mode_index = MODE_MAP.get(self.mode, -1)

        one_hot = [0.0] * MODE_COUNT
        if mode_index >= 0:
            one_hot[mode_index] = 1.0

        return [
            float(self.seq),
            float(self.temperature_c),
            float(self.battery_pct),
            float(self.latitude),
            float(self.longitude),
            float(self.altitude_km),
            float(self.bus_v),
            float(self.bus_i),
            *one_hot,
        ]

    def to_feature_dict(self) -> Dict[str, float]:
        """
        Named version (useful for CSV logging / debugging)
        """
        vec = self.to_feature_vector()

        keys = [
            "seq",
            "temperature_c",
            "battery_pct",
            "latitude",
            "longitude",
            "altitude_km",
            "bus_v",
            "bus_i",
            "mode_nominal",
            "mode_sunpoint",
            "mode_tx_window",
        ]

        return dict(zip(keys, vec))

    # ---------------------------------------------------------
    # Validation (for demo + explainability)
    # ---------------------------------------------------------

    def validate_envelope(self) -> list[str]:
        """
        Returns list of violations.
        Useful for:
        - demo explanations
        - ML reasoning display
        """

        issues: list[str] = []

        if not (0 <= self.battery_pct <= 100):
            issues.append("battery_out_of_range")

        if not (3.0 <= self.bus_v <= 6.0):
            issues.append("bus_voltage_anomaly")

        if not (0.0 <= self.bus_i <= 2.0):
            issues.append("bus_current_anomaly")

        if not (-100 <= self.temperature_c <= 120):
            issues.append("temperature_unrealistic")

        return issues

    # ---------------------------------------------------------
    # Mutation helper (for adversary simulation)
    # ---------------------------------------------------------

    def mutate_for_attack(self) -> "Telemetry":
        """
        Generate a clearly anomalous version for testing detection.
        """
        return self.clone_with(
            temperature_c=85.0,
            bus_v=2.1,
            bus_i=3.8,
            battery_pct=150,
            mode="UNKNOWN",
        )

    def clone_with(self, **updates: Any) -> "Telemetry":
        data = self.to_dict()
        data.update(updates)
        return Telemetry(**data)


# ---------------------------------------------------------------------
# Synthetic telemetry generator
# ---------------------------------------------------------------------

def sample_telemetry(seq: int) -> Telemetry:
    return Telemetry(
        seq=seq,
        timestamp=time.time(),
        temperature_c=21.4 + ((seq % 5) * 0.2),
        battery_pct=max(20, 100 - (seq % 15)),
        mode=["NOMINAL", "SUNPOINT", "TX_WINDOW"][seq % 3],
        latitude=43.0389 + ((seq % 3) * 0.001),
        longitude=-87.9065 - ((seq % 3) * 0.001),
        altitude_km=550.0 + ((seq % 4) * 0.1),
        bus_v=5.00 + ((seq % 4) * 0.03),
        bus_i=0.42 + ((seq % 5) * 0.01),
    )