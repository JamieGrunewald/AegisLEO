"""
satellite/mqtt_sender.py

Publishes telemetry packets to an MQTT broker.

Design notes (noob-friendly)
----------------------------
- MQTT is a pub/sub system:
    - Satellite = publisher
    - Ground station = subscriber
    - Broker = message router

- We treat MQTT as TRANSPORT ONLY.
  Our payload is still a binary Packet:
      [header | payload | crc]

- We use QoS 1 ("at least once") so messages are reliably delivered,
  but duplicates are possible. Our Packet has a sequence number (seq),
  which the ground station can use to detect duplicates if needed.
"""

from __future__ import annotations

import argparse
import time

import paho.mqtt.client as mqtt

from common.packet import Packet, encode_telemetry_json, now_ms


def build_telemetry(seq: int) -> dict:
    """
    Returns a simple telemetry dict. For now, values are static with a changing seq/time.
    Later this becomes real sensor data or simulated sensor streams.
    """
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

    # Create MQTT client.
    client = mqtt.Client(client_id=args.client_id, clean_session=True)

    # Optional: add callbacks for better logs while learning MQTT.
    def on_connect(client, userdata, flags, rc):
        # rc == 0 means success
        print(f"[satellite] connected to broker rc={rc}")

    def on_disconnect(client, userdata, rc):
        print(f"[satellite] disconnected rc={rc}")

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

    # Connect + start network loop in background thread.
    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()

    seq = 1
    period = 1.0 / max(args.hz, 0.1)

    print(
        f"[satellite] publishing to mqtt://{args.host}:{args.port} "
        f"topic='{args.topic}' qos={args.qos} rate={args.hz} Hz (Ctrl+C to stop)"
    )

    try:
        while True:
            telemetry = build_telemetry(seq)
            payload = encode_telemetry_json(telemetry)

            pkt = Packet(
                apid=args.apid,
                seq=seq,
                ts_ms=telemetry["ts_ms"],
                flags=0,
                payload=payload,
            )
            packet_bytes = pkt.to_bytes()

            # Publish binary packet bytes as MQTT payload.
            # retain=False because telemetry is "live stream" not state.
            info = client.publish(
                topic=args.topic,
                payload=packet_bytes,
                qos=args.qos,
                retain=False,
            )

            # info.rc is publish status; info.mid is message id.
            if seq % int(max(args.hz, 1)) == 0:
                print(f"[satellite] published seq={seq} mid={info.mid} bytes={len(packet_bytes)}")

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
