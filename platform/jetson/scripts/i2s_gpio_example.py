#!/usr/bin/env python

# Script to demonstrate I2S GPIO functionality on Jetson Orin
# Uses I2S0_DOUT as output and I2S0_DIN as input
# Requires physical connection between pin 40 (DOUT) and pin 38 (DIN)

import Jetson.GPIO as GPIO
import time

# Pin Definitions - using the Jetson Board Pin numbers
output_pin = 40  # I2S0_DOUT - Header pin 40
input_pin = 38   # I2S0_DIN - Header pin 38

def main():
    # Pin Setup:
    GPIO.setmode(GPIO.BOARD)  # Jetson board numbering scheme
    # Set pin 40 as output with initial state of HIGH
    GPIO.setup(output_pin, GPIO.OUT, initial=GPIO.HIGH)
    # Set pin 38 as input
    GPIO.setup(input_pin, GPIO.IN)

    print("Starting I2S GPIO test. Press CTRL+C to exit")
    print("Make sure pins 40 (DOUT) and 38 (DIN) are connected together")

    curr_output_value = GPIO.HIGH

    try:
        while True:
            # Toggle the output pin value
            GPIO.output(output_pin, curr_output_value)
            print(f"Output pin {output_pin} set to: {curr_output_value}")

            # Read the input pin value
            input_value = GPIO.input(input_pin)
            print(f"Input pin {input_pin} read as: {input_value}")

            # Verify if input matches output
            if input_value == curr_output_value:
                print("SUCCESS: Input matches output")
            else:
                print("FAILURE: Input doesn't match output")

            # Toggle the value for next iteration
            curr_output_value = GPIO.LOW if curr_output_value == GPIO.HIGH else GPIO.HIGH

            # Wait before next toggle
            time.sleep(1)
            print("--------------------------")

    except KeyboardInterrupt:
        print("\nExiting program")
    finally:
        GPIO.cleanup()
        print("GPIO pins cleaned up")

if __name__ == '__main__':
    main()
