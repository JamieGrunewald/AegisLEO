"""
AegisLEO Telemetry Visualizer

Created by: Jamie Grunewald
Date: 2026-03-23
Version: v0.1.0

Purpose
-------
Simple CLI tool to inspect and visualize telemetry logs.

This is intentionally lightweight and readable. It helps:
- inspect sequence behavior
- detect gaps
- view payload values over time

Future Enhancements
-------------------
- integrate anomaly scores from ML model
- export CSV
- plot graphs (matplotlib)
"""

from __future__ import annotations

import json
from pathlib import Path


LOG_DIR = Path("data/telemetry_logs")


def load_logs():
    """Load all JSON lines from telemetry log files."""
    entries = []

    if not LOG_DIR.exists():
        print(f"[WARN] Log directory not found: {LOG_DIR}")
        return entries

    for file in sorted(LOG_DIR.glob("*.log")):
        with open(file, "r") as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except Exception:
                    continue

    return entries


def analyze_sequences(entries):
    """Analyze sequence progression and detect gaps."""
    sequences = [e["sequence"] for e in entries if "sequence" in e]

    if not sequences:
        print("[INFO] No sequence data found")
        return

    sequences.sort()

    gaps = []
    for i in range(1, len(sequences)):
        if sequences[i] != sequences[i - 1] + 1:
            gaps.append((sequences[i - 1], sequences[i]))

    print("\n=== Sequence Analysis ===")
    print(f"Total packets: {len(sequences)}")
    print(f"Min seq: {min(sequences)}")
    print(f"Max seq: {max(sequences)}")

    if gaps:
        print("\nGaps detected:")
        for g in gaps:
            print(f"  Missing between {g[0]} -> {g[1]}")
    else:
        print("No gaps detected")


def print_samples(entries, limit=5):
    """Print sample telemetry entries."""
    print("\n=== Sample Telemetry ===")

    for e in entries[:limit]:
        payload = e.get("payload", {})
        print(
            f"seq={e.get('sequence')} "
            f"temp={payload.get('temp_c')} "
            f"voltage={payload.get('bus_v')} "
            f"state={payload.get('state')}"
        )


def main():
    entries = load_logs()

    if not entries:
        print("[INFO] No telemetry logs found.")
        return

    analyze_sequences(entries)
    print_samples(entries)


if __name__ == "__main__":
    main()