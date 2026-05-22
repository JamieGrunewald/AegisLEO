"""
AegisLEO — Feature Logger
===========================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0

Purpose
-------
Appends numeric telemetry feature rows to a CSV file for ML training data
collection. Called by groundstation/receiver.py on every successfully
decrypted and verified telemetry packet during live operation.

The generated CSV is consumed by models/generate_normal_dataset.py and
models/train_seq_autoencoder.py to train the anomaly detection autoencoder.

Output
------
groundstation/logs/telemetry_normal.csv (path configured at instantiation)
Columns match Telemetry.to_feature_dict() — see common/telemetry_model.py.

Used by
-------
- groundstation/receiver.py   (logs each verified telemetry frame)
- models/train_seq_autoencoder.py  (reads CSV for training)
"""

from __future__ import annotations

import csv
import os
from typing import Dict


class FeatureLogger:
    """
    Append numeric telemetry feature rows to a CSV file.

    Creates the output directory and writes a header row automatically
    on first use. Subsequent calls append rows without re-writing the header.

    Parameters
    ----------
    csv_path : str
        Full path to the output CSV file.
        Example: "groundstation/logs/telemetry_normal.csv"
    """

    def __init__(self, csv_path: str) -> None:
        self.csv_path = csv_path
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    def log(self, row: Dict[str, float]) -> None:
        """
        Append one telemetry feature row to the CSV.

        Parameters
        ----------
        row : dict
            Feature dict from Telemetry.to_feature_dict(). Keys become
            column headers on first write; subsequent rows must have
            the same keys in the same order.
        """
        file_exists = os.path.exists(self.csv_path)

        with open(self.csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(row.keys()))
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)
