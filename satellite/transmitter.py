import serial
import time

SERIAL_PORT = "/dev/ttyACM0"
#BAUD_RATE = 9600
BAUD_RATE = 115200

print("Opening serial port...")

ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

print("Satellite transmitter active")

counter = 0

while True:
    msg = f"PING {counter} from Pi-In-The-Sky\n"

    ser.write(msg.encode("utf-8"))
    ser.flush()

    print("TX:", msg.strip())

    counter += 1
    time.sleep(2)