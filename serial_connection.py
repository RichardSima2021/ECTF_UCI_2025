import serial
import serial.tools.list_ports



def serial_setup():
    #scan for available ports.
    ports = serial.tools.list_ports.comports(include_links=False)
    if len(ports) == 1:
        print("Auto port selected: " + ports[0].device)
        port = ports[0].device
    else:
        port = "COM6" #change this to your usual port
    serialPort = serial.Serial(port=port, baudrate=115200)

    while True:
        with open("serial_output.txt", "ab") as f:
            f.write(serialPort.read(4))



serial_setup()