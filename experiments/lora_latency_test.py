"""
AegisLEO LoRa Latency Test
---------------------------
Measures round-trip latency between satellite and ground station nodes
over the SX1262 LoRa serial link.

Run on ground station:
    python -m experiments.lora_latency_test --mode receiver

Run on satellite:
    python -m experiments.lora_latency_test --mode sender --port /dev/ttyACM0

Measures:
  - Time from frame TX to ACK RX (round-trip)
  - Frame loss rate at each chunk size
  - Effective throughput at nominal chunk sizes
"""

# TODO: implement latency measurement harness
# Depends on: radio/lora_serial.py, common/protocol.py
raise NotImplementedError("lora_latency_test not yet implemented — see docstring")
