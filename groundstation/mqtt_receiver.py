"""
AegisLEO — MQTT Ground Station Receiver (Early Prototype)
===========================================================

Created by: Jamie Grunewald
Date: 2026-03-08
Version: v0.1.0 (historical)

Purpose
-------
Early prototype of the ground station receiver using MQTT as the transport.
Subscribes to a topic on an MQTT broker, receives binary telemetry packets
published by satellite/mqtt_sender.py, and decodes them using the binary
Packet format (common/protocol.py).

This was developed alongside the UDP sender/receiver as an alternative
transport exploration before the LoRa RF link was introduced.

Status
------
Superseded by groundstation/receiver.py, which uses the LoRa serial link
with byte-stuffed framing, ML-KEM session key exchange, ML-DSA-65 signature
verification, AES-256-GCM decryption, replay protection, and ML anomaly
detection. Retained here as a reference for the project's development history.

Usage (historical)
------------------
    python -m groundstation.mqtt_receiver --host 127.0.0.1 --port 1883
"""

from __future__ import annotations

import argparse
import signal

import paho.mqtt.client as mqtt

from common.protocol import Packet, decode_telemetry_json


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1", help="MQTT broker host")
    ap.add_argument("--port", type=int, default=1883, help="MQTT broker port")
    ap.add_argument("--topic", default="satellite/demo-001/telemetry", help="MQTT topic")
    ap.add_argument("--client-id", default="groundstation-demo", help="MQTT client id")
    ap.add_argument("--qos", type=int, default=1, choices=[0, 1, 2], help="MQTT QoS")
    args = ap.parse_args()

    stop_flag = {"stop": False}

    def handle_sigint(sig, frame):
        stop_flag["stop"] = True
        print("\n[groundstation] stopping…")

    signal.signal(signal.SIGINT, handle_sigint)

    client = mqtt.Client(client_id=args.client_id, clean_session=True)

    def on_connect(client, userdata, flags, rc):
        print(f"[groundstation] connected rc={rc}")
        client.subscribe(args.topic, qos=args.qos)
        print(f"[groundstation] subscribed topic='{args.topic}' qos={args.qos}")

    def on_message(client, userdata, msg):
        try:
            pkt = Packet.from_bytes(msg.payload)
            telemetry = decode_telemetry_json(pkt.payload)
            print(
                f"[groundstation] topic={msg.topic} apid={pkt.apid} seq={pkt.seq} "
                f"ts_ms={pkt.ts_ms} telemetry={telemetry}"
            )
        except Exception as e:
            print(f"[groundstation] topic={msg.topic} BAD PACKET: {e}")

    def on_disconnect(client, userdata, rc):
        print(f"[groundstation] disconnected rc={rc}")

    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()

    print(f"[groundstation] listening mqtt://{args.host}:{args.port} (Ctrl+C to stop)")
    while not stop_flag["stop"]:
        signal.pause()

    client.loop_stop()
    client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
