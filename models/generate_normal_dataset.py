from __future__ import annotations

import csv
import os
import random

from common.telemetry import sample_telemetry

OUTPUT_PATH = "groundstation/logs/telemetry_normal.csv"
ROWS_TO_GENERATE = 2000


def main() -> None:
    os.makedirs("groundstation/logs", exist_ok=True)

    rows = []
    for seq in range(1, ROWS_TO_GENERATE + 1):
        t = sample_telemetry(seq)

        # Add tiny normal jitter so the model doesn't learn a dead-flat world.
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