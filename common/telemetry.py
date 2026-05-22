"""
AegisLEO — Telemetry Data Model
================================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.2.0

Purpose
-------
Defines the Telemetry dataclass used throughout AegisLEO as the canonical
representation of a satellite telemetry sample. Handles serialization,
ML feature extraction, envelope validation, and adversary mutation helpers.

Used by
-------
- satellite/transmitter.py       (generate + serialize samples)
- groundstation/receiver.py      (deserialize + display samples)
- models/runtime_detector.py     (feature vector input to autoencoder)
- groundstation/feature_logger.py (CSV logging for training data)
- adversary/kali-inj-bridge.py   (mutation for anomaly injection)

Version History
---------------
v0.2.0  Stable ML feature ordering, one-hot mode encoding, clone_with helper,
        validate_envelope hooks for demo explainability.
v0.1.0  Initial dataclass with JSON serialization.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, List
import json
import time

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
# Telemetry dataclass
# ---------------------------------------------------------------------

@dataclass
class Telemetry:
    """
    One satellite telemetry sample.

    Fields match the synthetic generator in sample_telemetry() and the
    payload schema in satellite/transmitter.py. The ML feature vector
    order is fixed — do not reorder fields once a model is trained.

    Attributes
    ----------
    seq : int
        Packet sequence number.
    timestamp : float
        UNIX timestamp at sample time.
    temperature_c : float
        On-board temperature in degrees Celsius.
    battery_pct : int
        Battery state of charge (0–100%).
    mode : str
        Spacecraft operating mode: NOMINAL, SUNPOINT, or TX_WINDOW.
    latitude : float
        Ground track latitude (degrees).
    longitude : float
        Ground track longitude (degrees).
    altitude_km : float
        Orbital altitude in kilometres.
    bus_v : float
        Power bus voltage (volts).
    bus_i : float
        Power bus current (amps).
    """

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
    # Human-readable output
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
        """Key-value pairs for structured demo output via demo_log.kv()."""
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
    # ML feature extraction
    # ---------------------------------------------------------

    def to_feature_vector(self) -> List[float]:
        """
        Fixed-order numeric feature vector for autoencoder input.

        Order: seq, temperature_c, battery_pct, latitude, longitude,
               altitude_km, bus_v, bus_i, mode_nominal, mode_sunpoint,
               mode_tx_window.

        WARNING: This order must never change once a model is trained.
        Changing it requires retraining from scratch.
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
        """Named version of the feature vector — useful for CSV logging."""
        vec = self.to_feature_vector()
        keys = [
            "seq", "temperature_c", "battery_pct",
            "latitude", "longitude", "altitude_km",
            "bus_v", "bus_i",
            "mode_nominal", "mode_sunpoint", "mode_tx_window",
        ]
        return dict(zip(keys, vec))

    # ---------------------------------------------------------
    # Envelope validation
    # ---------------------------------------------------------

    def validate_envelope(self) -> list[str]:
        """
        Check telemetry values against physically plausible bounds.

        Returns a list of violation strings (empty list = clean).
        Used by the demo for human-readable anomaly explanation alongside
        the autoencoder ThreatScore.
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
    # Mutation helpers (adversary simulation)
    # ---------------------------------------------------------

    def mutate_for_attack(self) -> "Telemetry":
        """Return a clearly anomalous variant for testing detection pipeline."""
        return self.clone_with(
            temperature_c=85.0,
            bus_v=2.1,
            bus_i=3.8,
            battery_pct=150,
            mode="UNKNOWN",
        )

    def clone_with(self, **updates: Any) -> "Telemetry":
        """Return a copy of this Telemetry with selected fields overridden."""
        data = self.to_dict()
        data.update(updates)
        return Telemetry(**data)


# ---------------------------------------------------------------------
# Synthetic telemetry generator
# ---------------------------------------------------------------------

def sample_telemetry(seq: int) -> Telemetry:
    """
    Generate a synthetic nominal telemetry sample for a given sequence number.

    Values cycle through small deterministic variations to simulate a live
    downlink. Used for training data generation and lab testing without
    physical hardware.
    """
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
