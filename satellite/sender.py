"""
satellite/sender.py

Simulates the "satellite" side of the demo by generating telemetry and sending it over UDP.

Why UDP?
--------
UDP is simple and fast for early development:
- one send() == one packet on the wire
- no connection setup
- easy to test locally on 127.0.0.1

Later we can swap to TCP for reliability, or LoRa/SDR for realism.
"""

from __future__ import annotations

import argparse
import socket
import time

from common.packet import Packet, encode_telemetry_json, now_ms


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
            # This dict is our "telemetry". Keep it simple and readable.
            telemetry = {
                "subsystem": "power",
                "bus_v": 12.1,
                "bus_i": 0.42,
                "temp_c": 33.7,
                "seq": seq,
                "ts_ms": now_ms(),
            }

            payload = encode_telemetry_json(telemetry)

            # Create a packet with a binary header + JSON payload.
            pkt = Packet(
                apid=args.apid,
                seq=seq,
                ts_ms=telemetry["ts_ms"],
                flags=0,
                payload=payload,
            )

            # Serialize + send as a single UDP datagram.
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
