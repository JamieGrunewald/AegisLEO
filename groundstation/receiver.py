import serial

SERIAL_PORT = "/dev/serial/by-id/usb-1a86_USB_Single_Serial_5AAF186928-if00"
#BAUD_RATE = 9600


ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=2)

print("Ground station listening")

while True:
    data = ser.readline()

    if data:
        msg = data.decode(errors="ignore").strip()
        print("RX:", msg)