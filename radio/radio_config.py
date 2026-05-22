"""
AegisLEO — Radio Configuration
================================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0 (stub)

Purpose
-------
Planned configuration loader for radio hardware parameters. In the current
pipeline, serial port paths and link constants (baud rate, chunk sizes,
frame delimiters) are defined as module-level constants in
satellite/transmitter.py and groundstation/receiver.py.

This module is reserved for v2.0 refactoring to centralize radio
configuration and support multiple hardware backends (SX1262 LoRa,
HackRF One, RTL-SDR v4) via a unified interface.

Configuration values live in config/radio.yaml.

Planned interface
-----------------
    cfg = RadioConfig.load("config/radio.yaml")
    cfg.serial_port          # "/dev/ttyACM0"
    cfg.baud_rate            # 115200
    cfg.max_frame_bytes      # 240
    cfg.telemetry_chunk_size # 110

See also
--------
- config/radio.yaml    — current link parameters
- radio/lora_serial.py — planned serial abstraction layer
"""

# TODO: implement RadioConfig loader from config/radio.yaml
