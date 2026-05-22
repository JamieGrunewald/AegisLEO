"""
AegisLEO — UDP Satellite Sender (Early Prototype)
===================================================

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.1.0 (historical)

Purpose
-------
Early prototype of the satellite transmitter using UDP as the transport.
Generates synthetic telemetry, wraps it in the binary Packet format
(common/protocol.py), and sends it as UDP datagrams to the ground station.

This was the first working end-to-end telemetry path in AegisLEO, used
to validate the packet format and CRC logic before the LoRa RF link was
introduced.

Status
------
Superseded by satellite/transmitter.py, which uses the LoRa serial link
with byte-stuffed framing, ML-KEM session key exchange, ML-DSA-65 signatures,
and AES-256-GCM encryption. Retained here as a reference for the project's
development history.

Usage (historical)
------------------
    python -m satellite.sender --host 127.0.0.1 --port 5005 --hz 2.0
"""

from __future__ import annotations

import argparse
import socket
import time

from common.protocol import Packet, encode_telemetry_json, now_ms


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1", help="Ground station host/IP")
    ap.add_argument("--port", type=int, default=5005, help="Ground station UDP port")
    ap.add_argument("--apid", type=int, default=42, help="Subsystem ID (APID)")
    ap.add_argument("--hz", type=float, default=2.0, help="Packets per second")
    args = ap.parse_args()

    addr = (args.host, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    seq = 1
    period = 1.0 / max(args.hz, 0.1)

    print(f"[satellite] sending UDP telemetry to {addr} at {args.hz} Hz (Ctrl+C to stop)")
    try:
        while True:
            telemetry = {
                "subsystem": "power",
                "bus_v": 12.1,
                "bus_i": 0.42,
                "temp_c": 33.7,
                "seq": seq,
                "ts_ms": now_ms(),
            }

            payload = encode_telemetry_json(telemetry)
            pkt = Packet(apid=args.apid, seq=seq, ts_ms=telemetry["ts_ms"], flags=0, payload=payload)
            sock.sendto(pkt.to_bytes(), addr)

            if seq % int(max(args.hz, 1)) == 0:
                print(f"[satellite] sent seq={seq}")

            seq += 1
            time.sleep(period)

    except KeyboardInterrupt:
        print("\n[satellite] stopped")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
