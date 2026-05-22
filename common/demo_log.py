# common/demo_log.py

"""
Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.02.0

Purpose:
- Consistent demo log style
- UTC timestamp
- Component + event labels
- Optional key/value fields
- Stage-friendly banners / sections
- Standardized crypto + ML verdict strings
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def _format_value(value: Any) -> str:
    """
    Render values in a stage-friendly way.

    Rules:
    - floats: trim to 4 decimals
    - bools: uppercase
    - everything else: str(...)
    """
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    return str(value)

def _fmt_fields(**fields: Any) -> str:
    parts: list[str] = []
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"{key}={_format_value(value)}")
    return " ".join(parts)

def dlog(component: str, event: str, message: str = "", **fields: Any) -> None:
    """
    Standard demo log line.

    Example:
    [01:22:10] [SAT] [TX_PACKET] Secure telemetry packet sent seq=12 chunks=4
    """
    suffix = _fmt_fields(**fields)
    line = f"[{_utc_ts()}] [{component}] [{event}]"
    if message:
        line += f" {message}"
    if suffix:
        line += f" {suffix}"
    print(line, flush=True)

def banner(title: str, width: int = 76) -> None:
    print("=" * width, flush=True)
    print(title, flush=True)
    print("=" * width, flush=True)

def section(title: str, width: int = 76) -> None:
    print("-" * width, flush=True)
    print(title, flush=True)
    print("-" * width, flush=True)

def kv(key: str, value: Any, width: int = 12) -> None:
    print(f"{key:<{width}}: {_format_value(value)}", flush=True)

def crypto_verdict(
    signature_valid: bool,
    session_active: bool,
    decrypt_ok: bool,
) -> str:
    return (
        f"signature={'VALID' if signature_valid else 'INVALID'}, "
        f"session={'ACTIVE' if session_active else 'INACTIVE'}, "
        f"decrypt={'SUCCESS' if decrypt_ok else 'FAILED'}"
    )

def ml_verdict(is_anomalous: bool, score: Any, reasons: Any = None) -> str:
    score_str = _format_value(score)

    if is_anomalous:
        if reasons:
            return f"ANOMALY score={score_str} reasons={reasons}"
        return f"ANOMALY score={score_str}"

    return f"NOMINAL score={score_str}"
