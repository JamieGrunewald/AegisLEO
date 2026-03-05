"""
groundstation/receiver.py

Simulates the "ground station" side:
- listens on UDP
- parses our packet format
- validates CRC
- decodes JSON telemetry
- prints a friendly log line

This is the simplest "end-to-end" proof that our packet format works.
"""

from __future__ import annotations

import argparse
import socket

from common.packet import Packet, decode_telemetry_json


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0", help="Bind address (0.0.0.0 = all interfaces)")
    ap.add_argument("--port", type=int, default=5005, help="UDP port to listen on")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))

    print(f"[groundstation] listening UDP on {(args.bind, args.port)} (Ctrl+C to stop)")

    while True:
        data, src = sock.recvfrom(65535)

        try:
            pkt = Packet.from_bytes(data)  # validates SYNC/version/length/CRC
            telemetry = decode_telemetry_json(pkt.payload)

            print(
                f"[groundstation] src={src} apid={pkt.apid} seq={pkt.seq} ts_ms={pkt.ts_ms} "
                f"telemetry={telemetry}"
            )
        except Exception as e:
            # Any parse/CRC errors come here.
            print(f"[groundstation] src={src} BAD PACKET: {e}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
