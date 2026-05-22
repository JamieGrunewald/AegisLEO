"""
AegisLEO — Kali Adversary Injection Bridge
============================================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0

Purpose
-------
Simulates an adversary node (Kali Linux VM on the same VLAN as the Jetson
ground station) injecting crafted telemetry packets into the AegisLEO
detection pipeline. Connects to a TCP bridge on the Orin that forwards
bytes into the receiver's serial buffer.

This script was developed for the CypherCon 9 live demo to show the
detection pipeline catching adversarial packets at two layers:
  1. Crypto layer  — ML-DSA-65 signature is invalid (Kali has no satellite
                     private key), so the receiver rejects immediately.
  2. ML layer      — Autoencoder reconstruction error spikes on anomalous
                     sensor values even in bypass/test mode.

Attack Profiles
---------------
spike    : Thermal spike (85C) + undervoltage + battery drain
drift    : Subtle orbital drift + gradual power degradation
flatline : All-zero sensor values (dead satellite spoof)

Usage
-----
    # Run on Kali or locally on Orin:
    python3 adversary/kali-inj-bridge.py --host 127.0.0.1 --port 5555 --profile spike

    # Inject via serial directly:
    python3 adversary/kali-inj-bridge.py --serial /dev/ttyACM0 --profile flatline

Note
----
tcp-inj-bridge.py is an alias for this file retained for naming clarity
during development. kali-inj-bridge.py is the canonical version.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import time
import zlib
import base64
import random


# ── Framing constants (must match receiver.py) ─────────────────────────
FRAME_START = b"\x7e"
FRAME_END   = b"\x7f"
FRAME_ESC   = 0x7d
FRAME_ESC_XOR = 0x20


# ── Anomalous telemetry profiles ───────────────────────────────────────
ATTACK_PROFILES = {
    "spike": {
        "description": "Thermal spike + power anomaly",
        "temp_c":      85.0,   # normal: ~21-23C
        "battery_pct": 12,     # normal: ~90-100%
        "bus_v":       2.1,    # normal: ~5.0V
        "bus_i":       1.85,   # normal: ~0.43A
        "state":       "SAFE_MODE",
        "latitude":    43.040,
        "longitude":   -87.907,
        "altitude_km": 550.1,
    },
    "drift": {
        "description": "Orbital drift + gradual battery drain",
        "temp_c":      31.5,
        "battery_pct": 45,
        "bus_v":       3.8,
        "bus_i":       0.95,
        "state":       "TX_WINDOW",
        "latitude":    43.040 + random.uniform(2.0, 5.0),
        "longitude":   -87.907 + random.uniform(2.0, 5.0),
        "altitude_km": 412.0,   # wrong orbit
    },
    "flatline": {
        "description": "All-zero sensor flatline (dead satellite spoof)",
        "temp_c":      0.0,
        "battery_pct": 0,
        "bus_v":       0.0,
        "bus_i":       0.0,
        "state":       "NOMINAL",
        "latitude":    0.0,
        "longitude":   0.0,
        "altitude_km": 0.0,
    },
}


def stuff_length(length_bytes: bytes) -> bytes:
    """Byte-stuff the 4-byte length field to match receiver framing."""
    out = bytearray()
    for b in length_bytes:
        if b in (0x7e, 0x7f, 0x7d):
            out.append(FRAME_ESC)
            out.append(b ^ FRAME_ESC_XOR)
        else:
            out.append(b)
    return bytes(out)


def build_crafted_frame(seq: int, profile: dict) -> bytes:
    """
    Build a fake transport chunk that looks like a telemetry packet.
    The signature will be garbage — crypto layer will catch it.
    The payload values will be anomalous — ML layer will catch it.
    """
    # Build a fake decrypted payload matching what receiver expects
    # after reassembly. We inject at the logical packet level by
    # crafting a single-chunk session with a fake signature.
    fake_payload = {
        "type": "telemetry",
        "spacecraft_id": "AegisLEO-SAT-1",
        "session_id": "deadbeefdeadbeef",  # fake session
        "nonce": base64.b64encode(b"\x00" * 12).decode(),
        "ciphertext": base64.b64encode(json.dumps({
            "spacecraft_id": "AegisLEO-SAT-1",
            "apid": 100,
            "sequence": seq,
            "timestamp": time.time(),
            "payload": {
                "temp_c":      profile["temp_c"],
                "battery_pct": profile["battery_pct"],
                "bus_v":       profile["bus_v"],
                "bus_i":       profile["bus_i"],
                "state":       profile["state"],
                "latitude":    profile["latitude"],
                "longitude":   profile["longitude"],
                "altitude_km": profile["altitude_km"],
            }
        }).encode()).decode(),
        "signature": base64.b64encode(b"\xff" * 32).decode(),  # garbage sig
    }

    # Wrap as a single transport chunk (t=tc, i=0, n=1)
    data = base64.b64encode(
        json.dumps(fake_payload, separators=(",", ":")).encode()
    ).decode()

    chunk = {
        "t": "tc",
        "sid": "deadbeefdeadbeef",
        "mid": seq,
        "i": 0,
        "n": 1,
        "d": data,
        "c": zlib.crc32(data.encode()) & 0xFFFFFFFF,
    }

    payload_bytes = json.dumps(chunk, separators=(",", ":")).encode("utf-8")
    length_stuffed = stuff_length(len(payload_bytes).to_bytes(4, "big"))
    return FRAME_START + length_stuffed + payload_bytes + FRAME_END


def send_via_tcp(host: str, port: int, frames: list[bytes]) -> None:
    """Send crafted frames to a TCP bridge on the Orin."""
    with socket.create_connection((host, port), timeout=5) as sock:
        for frame in frames:
            sock.sendall(frame)
            print(f"[KALI] Sent {len(frame)} bytes to {host}:{port}")
            time.sleep(0.5)


def send_via_serial(port: str, frames: list[bytes]) -> None:
    """Send crafted frames directly to the Orin's serial port (local only)."""
    import serial as pyserial
    with pyserial.Serial(port, 115200, timeout=1) as ser:
        for frame in frames:
            ser.write(frame)
            ser.flush()
            print(f"[KALI] Injected {len(frame)} bytes via {port}")
            time.sleep(0.5)


def print_banner(profile_name: str, profile: dict) -> None:
    print()
    print("=" * 60)
    print("  AegisLEO — Kali Adversary Injection")
    print("=" * 60)
    print(f"  Attack profile : {profile_name}")
    print(f"  Description    : {profile['description']}")
    print(f"  Injecting      : temp={profile['temp_c']}C  "
          f"battery={profile['battery_pct']}%  "
          f"bus_v={profile['bus_v']}V")
    print()
    print("  Expected results:")
    print("    Crypto : signature=INVALID  (can't forge ML-DSA-65)")
    print("    ML     : ANOMALY            (autoencoder flags values)")
    print("=" * 60)
    print()


def main() -> None:
    ap = argparse.ArgumentParser(description="AegisLEO Kali injection demo")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Target Orin IP (default: localhost)")
    ap.add_argument("--port", type=int, default=5555,
                    help="TCP bridge port on Orin")
    ap.add_argument("--serial", default=None,
                    help="Serial port for direct injection (e.g. /dev/ttyACM0)")
    ap.add_argument("--profile", default="spike",
                    choices=list(ATTACK_PROFILES.keys()),
                    help="Attack profile to use")
    ap.add_argument("--count", type=int, default=5,
                    help="Number of crafted packets to inject")
    ap.add_argument("--delay", type=float, default=2.0,
                    help="Delay between injections (seconds)")
    args = ap.parse_args()

    profile = ATTACK_PROFILES[args.profile]
    print_banner(args.profile, profile)

    frames = []
    for i in range(args.count):
        frame = build_crafted_frame(seq=1000 + i, profile=profile)
        frames.append(frame)
        print(f"[KALI] Built frame {i+1}/{args.count}  "
              f"({len(frame)} bytes)  seq={1000+i}")

    print()

    if args.serial:
        print(f"[KALI] Injecting via serial: {args.serial}")
        send_via_serial(args.serial, frames)
    else:
        print(f"[KALI] Injecting via TCP: {args.host}:{args.port}")
        send_via_tcp(args.host, args.port, frames)

    print()
    print("[KALI] Injection complete. Check ground station output.")
    print()


if __name__ == "__main__":
    main()
