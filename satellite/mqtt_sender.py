"""
AegisLEO — MQTT Satellite Sender (Early Prototype)
====================================================

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.1.0 (historical)

Purpose
-------
Early prototype of the satellite transmitter using MQTT as the transport.
Publishes binary telemetry packets to an MQTT broker using paho-mqtt.
The ground station subscribes to the same topic to receive packets.

This explored MQTT as an alternative transport to UDP before the LoRa RF
link was introduced. MQTT's pub/sub model was considered for multi-ground-
station scenarios.

Status
------
Superseded by satellite/transmitter.py, which uses the LoRa serial link
with byte-stuffed framing, ML-KEM session key exchange, ML-DSA-65 signatures,
and AES-256-GCM encryption. Retained here as a reference for the project's
development history.

Usage (historical)
------------------
    python -m satellite.mqtt_sender --host 127.0.0.1 --port 1883 --hz 2.0
"""

from __future__ import annotations

import argparse
import time

import paho.mqtt.client as mqtt

from common.protocol import Packet, encode_telemetry_json, now_ms


def build_telemetry(seq: int) -> dict:
    return {
        "subsystem": "power",
        "bus_v": 12.1,
        "bus_i": 0.42,
        "temp_c": 33.7,
        "seq": seq,
        "ts_ms": now_ms(),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1", help="MQTT broker host")
    ap.add_argument("--port", type=int, default=1883, help="MQTT broker port")
    ap.add_argument("--topic", default="satellite/demo-001/telemetry", help="MQTT topic")
    ap.add_argument("--client-id", default="satellite-demo-001", help="MQTT client id")
    ap.add_argument("--apid", type=int, default=42, help="Packet APID (subsystem id)")
    ap.add_argument("--hz", type=float, default=2.0, help="Packets per second")
    ap.add_argument("--qos", type=int, default=1, choices=[0, 1, 2], help="MQTT QoS")
    args = ap.parse_args()

    client = mqtt.Client(client_id=args.client_id, clean_session=True)
    client.on_connect = lambda c, u, f, rc: print(f"[satellite] connected rc={rc}")
    client.on_disconnect = lambda c, u, rc: print(f"[satellite] disconnected rc={rc}")

    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()

    seq = 1
    period = 1.0 / max(args.hz, 0.1)

    print(f"[satellite] publishing to mqtt://{args.host}:{args.port} topic='{args.topic}' (Ctrl+C to stop)")

    try:
        while True:
            telemetry = build_telemetry(seq)
            payload = encode_telemetry_json(telemetry)
            pkt = Packet(apid=args.apid, seq=seq, ts_ms=telemetry["ts_ms"], flags=0, payload=payload)
            info = client.publish(topic=args.topic, payload=pkt.to_bytes(), qos=args.qos, retain=False)

            if seq % int(max(args.hz, 1)) == 0:
                print(f"[satellite] published seq={seq} mid={info.mid}")

            seq += 1
            time.sleep(period)

    except KeyboardInterrupt:
        print("\n[satellite] stopping…")
    finally:
        client.loop_stop()
        client.disconnect()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
