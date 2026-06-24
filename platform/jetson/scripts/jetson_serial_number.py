#!/usr/lib/ark-os/venv/bin/python3

import smbus2


def main():
    try:
        # Read the 128-bit serial from the AT24CSW010 EEPROM on I2C bus 7 (address 0x58).
        # The read needs a dummy write of a word address that begins with the 10b sequence
        # (0x80); any other word address makes the device return invalid data.
        bus = smbus2.SMBus(7)
        address = 0x58
        bus.write_byte(address, 0x80)
        serial_number = bus.read_i2c_block_data(address, 0x80, 16)
        return ''.join('{:02x}'.format(byte) for byte in serial_number)
    except Exception:
        return None


if __name__ == '__main__':
    serial_number = main()
    if serial_number:
        print(serial_number)
    else:
        print('unknown')
        raise SystemExit(1)
