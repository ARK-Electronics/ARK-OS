import spidev
import time
# import Jetson.GPIO as GPIO

# SPI and GPIO Configuration
SPI_BUS = 1     # SPI1
SPI_DEVICE = 0  # CSN0
DRDY_PIN = 7    # GPIO07 (BCM numbering assumed)

# Register Constants
WHO_AM_I = 0x75
DEVICE_ID = 0x47

DEVICE_CONFIG = 0x11
SOFT_RESET = 0x01

REG_BANK_SEL = 0x76

# Register Bank 0 (default)
PWR_MGMT0 = 0x4E
GYRO_CONFIG0 = 0x4F
ACCEL_CONFIG0 = 0x50
INT_STATUS = 0x2D
ACCEL_XOUT_H = 0x1F

ACCEL_SCALE = 9.80665 / 2048  # m/s^2 per LSB
GYRO_SCALE = (3.141592653589793 / 180) / 16.4  # rad/s per LSB

class ICM42688P:
    def __init__(self):
        self.spi = spidev.SpiDev()
        self.spi.open(SPI_BUS, SPI_DEVICE)
        self.spi.max_speed_hz = 1000000
        self.spi.mode = 0b00

        # GPIO.setmode(GPIO.BOARD)
        # GPIO.setup(DRDY_PIN, GPIO.IN)

        self._initialize_device()

    def _write_register(self, reg, value):
        self.spi.xfer2([reg & 0x7F, value])  # MSB=0 for write

    def _read_register(self, reg, length=1):
        result = self.spi.xfer2([reg | 0x80] + [0x00]*length)
        return result[1:] if length > 1 else result[1]

    def _select_register_bank(self, bank):
        self._write_register(REG_BANK_SEL, bank << 4)

    def _initialize_device(self):
        self._write_register(DEVICE_CONFIG, SOFT_RESET)
        time.sleep(0.1)
        whoami = self._read_register(WHO_AM_I)
        if whoami != DEVICE_ID:
            raise RuntimeError(f"ICM-42688-P not found! WHO_AM_I={whoami:#x}")

        self._write_register(PWR_MGMT0, 0x0F)  # Enable accel & gyro, low-noise mode
        self._write_register(GYRO_CONFIG0, 0x06)   # 1kHz ODR, ±2000 dps
        self._write_register(ACCEL_CONFIG0, 0x06)  # 1kHz ODR, ±16g
        print("ICM-42688-P initialized.")

    def _read_sensor_data(self):
        data = self._read_register(ACCEL_XOUT_H, 14)
        ax = self._combine(data[0], data[1]) * (9.80665 / 2048)
        ay = self._combine(data[2], data[3]) * (9.80665 / 2048)
        az = self._combine(data[4], data[5]) * (9.80665 / 2048)

        gx = self._combine(data[6], data[7]) * (3.141592653589793 / 180 / 16.4)
        gy = self._combine(data[8], data[9]) * (3.141592653589793 / 180 / 16.4)
        gz = self._combine(data[10], data[11]) * (3.141592653589793 / 180 / 16.4)

        raw_temp = self._combine(data[12], data[13])
        temp_c = (raw_temp / 132.48) + 25

        return {
            'accel': (ax, ay, az),   # in m/s^2
            'gyro': (gx, gy, gz),    # in rad/s
            'temp': temp_c             # raw
        }


    def _combine(self, high, low):
        val = (high << 8) | low
        return val - 65536 if val & 0x8000 else val

    def close(self):
        self.spi.close()
        # GPIO.cleanup()

    def wait_for_data_ready(self):
        # GPIO.wait_for_edge(DRDY_PIN, GPIO.RISING)
        pass

# Example usage
if __name__ == '__main__':
    imu = ICM42688P()
    try:
        while True:
            #imu.wait_for_data_ready()
            data = imu._read_sensor_data()
            print(f"Accel: {data['accel']}, Gyro: {data['gyro']}, Temp: {data['temp']}")
    finally:
        imu.close()
