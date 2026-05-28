#!/usr/lib/ark-os/venv/bin/python3

import smbus2

def main():

    try:
        # Read the serial number from AT24CSW010 on I2C bus 7. Address 0x50 and 0x58 are used for the EEPROM.

        # Reading the 128-bit serial number is similar to the sequential read sequence, but requires use of the device address
        # seen in a dummy write and a specific word address. The word address must begin with a 10b sequence regardless
        # of the intended address. If a word address other than 10b is used, the device will not output valid data.

        bus = smbus2.SMBus(7)

        # Read the serial number from the first EEPROM
        address = 0x58

        # Write the word address
        bus.write_byte(address, 0x80)

        # Read the serial number. First 32 bytes are the serial number. Second 16 bytes are writeable.
        serial_number = bus.read_i2c_block_data(address, 0x80, 16)

        # Convert to hex
        serial_number = ''.join('{:02x}'.format(x) for x in serial_number)

        print('ARK Jetson Carrier Serial: ' + serial_number)

        return serial_number
    except Exception as e:
        print('Error: ' + str(e))

        # if error is permission denied, run the following command:
        # sudo usermod -a -G i2c $USER

        print('Serial Number Chip Not Found')
        return -1

if __name__ == '__main__':
    main()
