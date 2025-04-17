from smbus2 import SMBus
import time
import math

# INA238 Register Addresses
REG_CONFIG = 0x00
REG_ADC_CONFIG = 0x01
REG_SHUNT_CAL = 0x02
REG_VSHUNT = 0x04
REG_VBUS = 0x05
REG_DIETEMP = 0x06
REG_CURRENT = 0x07
REG_POWER = 0x08

# Conversion factors
VSHUNT_LSB = 5e-6  # 5 µV/LSB for ADCRANGE = 0
VBUS_LSB = 3.125e-3  # 3.125 mV/LSB
TEMP_LSB = 0.125  # 125 m°C/LSB
POWER_LSB_MULTIPLIER = 0.2

class INA238:
    def __init__(self, bus_num=7, address=0x45, r_shunt=0.001, i_max=70.7):
        self.bus = SMBus(bus_num)
        self.address = address
        self.r_shunt = r_shunt
        #  Current_LSB = MaxExpectedCurrent / 2^15
        self.current_lsb = i_max / 32768  # Max 16-bit signed
        self.power_lsb = self.current_lsb * POWER_LSB_MULTIPLIER
        # SHUNT_CAL = 819.2 x 10^6 x CURRENT_LSB x R_shunt
        self.shunt_cal = int(819.2e6 * self.current_lsb * self.r_shunt)

        self.configure()

    def configure(self):
        # Default CONFIG: ADCRANGE = 0 (±163.84mV), CONVDLY = 0
        self.write_register(REG_CONFIG, 0x0000)

        # ADC_CONFIG: continuous conversion on all (bus, shunt, temp), 1052µs conv time, AVG = 16
        adc_config = (0xF << 12) | (5 << 9) | (5 << 6) | (5 << 3) | 2
        self.write_register(REG_ADC_CONFIG, adc_config)

        # SHUNT_CAL: The register provides the device with a conversion constant value
        # that represents shunt resistance used to calculate current value in Amperes.
        #  This also sets the resolution for the CURRENT register.
        self.write_register(REG_SHUNT_CAL, self.shunt_cal)

    def write_register(self, reg, value):
        data = [(value >> 8) & 0xFF, value & 0xFF]
        self.bus.write_i2c_block_data(self.address, reg, data)

    def read_register(self, reg, length=2):
        data = self.bus.read_i2c_block_data(self.address, reg, length)
        value = int.from_bytes(data, byteorder='big', signed=(reg != REG_POWER))
        return value

    def read_shunt_voltage(self):
        raw = self.read_register(REG_VSHUNT)
        return raw * VSHUNT_LSB

    def read_bus_voltage(self):
        raw = self.read_register(REG_VBUS)
        return raw * VBUS_LSB

    def read_temperature(self):
        raw = self.read_register(REG_DIETEMP)
        # Top 12 bits are the temperature
        raw_temp = raw >> 4
        # Convert 12-bit two's complement
        if raw_temp & 0x800:  # negative value
            raw_temp -= 1 << 12
        return raw_temp * TEMP_LSB

    def read_current(self):
        raw = self.read_register(REG_CURRENT)
        # Current [A] = CURRENT_LSB x CURRENT
        return raw * self.current_lsb

    def read_power(self):
        raw = self.read_register(REG_POWER, length=3)
        # Power [W] = 0.2 x CURRENT_LSB x POWER
        return raw * self.power_lsb

    def close(self):
        self.bus.close()


if __name__ == "__main__":
    # 1mOhm 5W shunt
    # power = I * I * R --> sqrt(5W / 0.001) = 70.7107
    power_rating = 5 # Watts
    shunt_resistance = 0.001 # Ohms
    max_current = math.sqrt(power_rating / shunt_resistance)
    ina = INA238(r_shunt=shunt_resistance, i_max=max_current)
    try:
        while True:
            print(f"Bus Voltage: {ina.read_bus_voltage():.3f} V")
            print(f"Shunt Voltage: {ina.read_shunt_voltage():.6f} V")
            print(f"Current: {ina.read_current():.3f} A")
            print(f"Power: {ina.read_power():.3f} W")
            print(f"Temperature: {ina.read_temperature():.2f} °C")
            print("-" * 40)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        ina.close()
