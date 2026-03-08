"""
AegisLEO Ground Station LoRa Test

Created by: Jamie Grunewald
Date: 2026-03-08
System: Raspberry Pi (Satellite Simulator)

Purpose:
1. Listen for messages from the ground station
2. When the expected message arrives, respond with:
       "You got it"

This simulates a spacecraft acknowledging a command
from the ground station.

Ground station message:
    "This transmission is coming to you. This transmission is coming to you."

Satellite response:
    "You got it"
"""

import serial   #used to talk to serial devices (USB radios)
import time     #used for timing and delays


# -------------------------------------------------------------------
# SERIAL DEVICE SETTINGS
# -------------------------------------------------------------------

# Serial device where the LoRa USB adapter appears on the Pi
SERIAL_PORT = "/dev/ttyACM0"

# Must match the baud rate used by the ground station
BAUD_RATE = 115200


# -------------------------------------------------------------------
# MESSAGE DEFINITIONS
# -------------------------------------------------------------------

# Message expected from the ground station
EXPECTED_MESSAGE = (
    "This transmission is coming to you. "
    "This transmission is coming to you."
)

# Satellite reply
RESPONSE_MESSAGE = "You got it\n"


# -------------------------------------------------------------------
# OPEN SERIAL CONNECTION
# -------------------------------------------------------------------

# Connect to the LoRa modem over USB serial
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

print("Satellite node online")
print(f"Listening on {SERIAL_PORT} at {BAUD_RATE} baud")


# -------------------------------------------------------------------
# MAIN LISTENING LOOP
# -------------------------------------------------------------------

while True:

    # Read a line of incoming serial data from the radio
    data = ser.readline()

    if data:

        # Convert raw bytes into readable text
        msg = data.decode("utf-8", errors="replace").strip()

        print("SAT RX:", msg)

        # -----------------------------------------------------------
        # CHECK IF MESSAGE MATCHES EXPECTED COMMAND
        # -----------------------------------------------------------

        if msg == EXPECTED_MESSAGE:

            # Send response back to the ground station
            ser.write(RESPONSE_MESSAGE.encode("utf-8"))
            ser.flush()

            print("SAT TX:", RESPONSE_MESSAGE.strip())

    # Short delay prevents the loop from using 100% CPU
    time.sleep(0.1)