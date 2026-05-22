"""
AegisLEO — Normal Telemetry Dataset Generator
===============================================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0

Purpose
-------
Generates a synthetic CSV dataset of nominal satellite telemetry for
training the sequence autoencoder anomaly detector. Samples are drawn
from the same deterministic generator used by the live transmitter
(common/telemetry_model.py::sample_telemetry), with small random jitter added
so the model learns a realistic distribution rather than a dead-flat signal.

Output
------
groundstation/logs/telemetry_normal.csv — 2000 rows, one per telemetry sample.
Columns match the feature vector defined in Telemetry.to_feature_dict().

Usage
-----
    python -m models.generate_normal_dataset

Run this once before training. The output CSV is consumed by
models/train_seq_autoencoder.py via models/window_dataset.py.
"""

from __future__ import annotations

import csv
import os
import random

from common.telemetry_model import sample_telemetry

OUTPUT_PATH = "groundstation/logs/telemetry_normal.csv"
ROWS_TO_GENERATE = 2000


def main() -> None:
    os.makedirs("groundstation/logs", exist_ok=True)

    rows = []
    for seq in range(1, ROWS_TO_GENERATE + 1):
        t = sample_telemetry(seq)

        # Add small random jitter so the model learns a realistic distribution
        # rather than memorizing a perfectly repeating pattern.
        t = t.clone_with(
            temperature_c=t.temperature_c + random.uniform(-0.15, 0.15),
            bus_v=t.bus_v + random.uniform(-0.02, 0.02),
            bus_i=t.bus_i + random.uniform(-0.01, 0.01),
            latitude=t.latitude + random.uniform(-0.0003, 0.0003),
            longitude=t.longitude + random.uniform(-0.0003, 0.0003),
            altitude_km=t.altitude_km + random.uniform(-0.05, 0.05),
        )

        rows.append(t.to_feature_dict())

    with open(OUTPUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
