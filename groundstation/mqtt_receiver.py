"""
groundstation/mqtt_receiver.py

Subscribes to telemetry packets from MQTT and decodes them.

What we verify here:
- Packet parse success
- CRC32 matches (catches corruption/tamper)

What we do NOT do yet:
- AES-GCM authentication
- Dilithium signature verification

Those are the next layer and will fit cleanly because the MQTT payload is already binary.
"""

from __future__ import annotations

import argparse
import signal
import sys
from typing import Optional

import paho.mqtt.client as mqtt

from common.packet import Packet, decode_telemetry_json


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
        # msg.payload is bytes; exactly what satellite published.
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
