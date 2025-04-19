#!/usr/bin/env python

# Script to demonstrate I2S GPIO functionality on ARK Jetson Carrier
# Uses I2S0_DOUT as output and I2S0_DIN as input
# Requires physical connection between pin 40 (DOUT) and pin 38 (DIN)

import Jetson.GPIO as GPIO
import time

output_pin = 40  # I2S0_DOUT - Header pin 40
input_pin = 38   # I2S0_DIN - Header pin 38

def main():
    GPIO.setmode(GPIO.BOARD)  # Jetson board numbering scheme
    GPIO.setup(output_pin, GPIO.OUT, initial=GPIO.HIGH)
    GPIO.setup(input_pin, GPIO.IN)

    print("Starting I2S GPIO test. Press CTRL+C to exit")
    print("Make sure pins 40 (DOUT) and 38 (DIN) are connected together")

    curr_output_value = GPIO.HIGH

    try:
        while True:
            GPIO.output(output_pin, curr_output_value)
            print(f"Output pin {output_pin} set to: {curr_output_value}")

            input_value = GPIO.input(input_pin)
            print(f"Input pin {input_pin} read as: {input_value}")

            if input_value == curr_output_value:
                print("SUCCESS: Input matches output")
            else:
                print("FAILURE: Input doesn't match output")

            curr_output_value = GPIO.LOW if curr_output_value == GPIO.HIGH else GPIO.HIGH

            time.sleep(1)
            print("--------------------------")

    except KeyboardInterrupt:
        print("\nExiting program")
    finally:
        GPIO.cleanup()
        print("GPIO pins cleaned up")

if __name__ == '__main__':
    main()
