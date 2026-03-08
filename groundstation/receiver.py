"""
AegisLEO Ground Station LoRa Test

Created by: Jamie Grunewald
Date: 2026-03-08
System: Jetson Orin Nano Super Dev(Ground Station)

Purpose:
1. Send a challenge message to the satellite over LoRa
2. Wait for a response
3. Print the received reply

This proves two-way communication over the LoRa radio link.

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

# This is the stable device path for the LoRa adapter on the Orin.
# Using /dev/serial/by-id prevents device name changes after reboot.
SERIAL_PORT = "/dev/serial/by-id/usb-1a86_USB_Single_Serial_5AAF186928-if00"

# UART communication speed.
# This must match the configuration of the LoRa module.
BAUD_RATE = 115200


# -------------------------------------------------------------------
# MESSAGE DEFINITIONS
# -------------------------------------------------------------------

# Message sent by the ground station to the satellite
GROUND_MESSAGE = (
    "This transmission is coming to you. "
    "This transmission is coming to you.\n"
)


# -------------------------------------------------------------------
# OPEN SERIAL CONNECTION TO LORA MODEM
# -------------------------------------------------------------------

# Create a serial object that connects to the LoRa radio.
# timeout=1 means the read operation waits up to 1 second for data.
ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

print(f"Ground station online")
print(f"Connected to {SERIAL_PORT} at {BAUD_RATE} baud")


# Give the radio a moment to stabilize before sending traffic
time.sleep(2)


# -------------------------------------------------------------------
# MAIN COMMUNICATION LOOP
# -------------------------------------------------------------------

while True:

    # ---------------------------------------------------------------
    # STEP 1: SEND MESSAGE TO SATELLITE
    # ---------------------------------------------------------------

    # Convert the Python string into bytes and send it over serial.
    ser.write(GROUND_MESSAGE.encode("utf-8"))

    # Flush ensures the data leaves the USB buffer immediately.
    ser.flush()

    print("GROUND TX:", GROUND_MESSAGE.strip())


    # ---------------------------------------------------------------
    # STEP 2: WAIT FOR RESPONSE FROM SATELLITE
    # ---------------------------------------------------------------

    # We will listen for up to 3 seconds for the satellite reply.
    start_time = time.time()

    while time.time() - start_time < 3:

        # Read a line of incoming data from the radio
        data = ser.readline()

        if data:

            # Convert received bytes into readable text
            msg = data.decode("utf-8", errors="replace").strip()

            print("GROUND RX:", msg)

    # Wait before sending the next message
    time.sleep(2)