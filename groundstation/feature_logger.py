from __future__ import annotations

import csv
import os
from typing import Dict


class FeatureLogger:
    """
    Append numeric telemetry features to a CSV file for ML training.
    """

    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    def log(self, row: Dict[str, float]) -> None:
        file_exists = os.path.exists(self.csv_path)

        with open(self.csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(row.keys()))
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)