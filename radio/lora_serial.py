"""
AegisLEO — LoRa Serial Driver
===============================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0 (stub)

Purpose
-------
Planned abstraction layer for the SX1262 LoRa serial link. In the current
pipeline, serial I/O is handled directly in satellite/transmitter.py and
groundstation/receiver.py using pyserial with byte-stuffed framing.

This module is reserved for v2.0 refactoring, where the radio layer will
be replaced by HackRF One (TX) + RTL-SDR v4 (RX) for true over-the-air
testing. GNU Radio will handle channel modeling (Doppler, AWGN).

Planned interface
-----------------
    radio = LoraSerial(port="/dev/ttyACM0", baud=115200)
    radio.write_frame(payload_bytes)
    frame = radio.read_frame(timeout=5.0)

See also
--------
- config/radio.yaml    — serial port and link parameters
- docs/architecture.md — v2.0 RF hardware roadmap
"""

# TODO: implement LoRa serial abstraction for v2.0 HackRF/RTL-SDR migration
