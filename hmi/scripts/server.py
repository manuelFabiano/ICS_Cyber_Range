#!/usr/bin/env python
from pymodbus.client import ModbusTcpClient as ModbusClient
import time

client = ModbusClient('172.29.0.2', port=502)

unit=0x01

# Get the initial state
rr = client.read_coils(0, 1, unit=unit)
print("Initial LED output: " + str(rr.getBit(0)))
time.sleep(1)

client.write_coil(1, True, unit=unit)
print("Pressed PB1 - turn on LED")
time.sleep(1)

client.write_coil(1, False, unit=unit)
print("Unpressed PB1")
time.sleep(1)

rr = client.read_coils(0, 1, unit=unit)
print("LED output after pressing PB1: " + str(rr.getBit(0)))
time.sleep(1)

client.write_coil(2, True, unit=unit)
print("Pressed PB2 - reset")
time.sleep(1)

client.write_coil(2, False, unit=unit)
print("Unpressed PB2")
time.sleep(1)

rr = client.read_coils(0, 1, unit=unit)
print("LED output after pressing PB2 (reset): " + str(rr.getBit(0)))
time.sleep(1)

client.close()

