#!/usr/lib/ark-os/venv/bin/python3

"""
Open a shell over MAVLink.

@author: Beat Kueng (beat-kueng@gmx.net)
"""

# HINT: ./px4_shell_command.py "m95040df -S -b 1 -c 1 id 2"

from __future__ import print_function
import sys, select
import termios
from timeit import default_timer as timer
from argparse import ArgumentParser
import os

try:
    from pymavlink import mavutil
except ImportError as e:
    print("Failed to import pymavlink: " + str(e))
    print("")
    print("You may need to install it with:")
    print("    pip3 install --user pymavlink")
    print("")
    sys.exit(1)

try:
    import serial
except ImportError as e:
    print("Failed to import pyserial: " + str(e))
    print("")
    print("You may need to install it with:")
    print("    pip3 install --user pyserial")
    print("")
    sys.exit(1)


class MavlinkSerialPort():
    '''an object that looks like a serial port, but
    transmits using mavlink SERIAL_CONTROL packets'''
    def __init__(self, portname, baudrate, devnum=0, debug=0):
        self.baudrate = 0
        self._debug = debug
        self.buf = ''
        self.port = devnum
        self.debug("Connecting with MAVLink to %s ..." % portname)
        self.mav = mavutil.mavlink_connection(portname, autoreconnect=True, baud=baudrate)
        self.mav.wait_heartbeat()
        self.debug("HEARTBEAT OK\n")
        self.debug("Locked serial device\n")

    def debug(self, s, level=1):
        '''write some debug text'''
        if self._debug >= level:
            print(s)

    def write(self, b):
        '''write some bytes'''
        self.debug("sending '%s' (0x%02x) of len %u\n" % (b, ord(b[0]), len(b)), 2)
        while len(b) > 0:
            n = len(b)
            if n > 70:
                n = 70
            buf = [ord(x) for x in b[:n]]
            buf.extend([0]*(70-len(buf)))
            self.mav.mav.serial_control_send(self.port,
                                             mavutil.mavlink.SERIAL_CONTROL_FLAG_EXCLUSIVE |
                                             mavutil.mavlink.SERIAL_CONTROL_FLAG_RESPOND,
                                             0,
                                             0,
                                             n,
                                             buf)
            b = b[n:]

    def close(self):
        self.mav.mav.serial_control_send(self.port, 0, 0, 0, 0, [0]*70)

    def _recv(self):
        '''read some bytes into self.buf'''
        m = self.mav.recv_match(condition='SERIAL_CONTROL.count!=0',
                                type='SERIAL_CONTROL', blocking=True,
                                timeout=0.03)
        if m is not None:
            if self._debug > 2:
                print(m)
            data = m.data[:m.count]
            self.buf += ''.join(str(chr(x)) for x in data)

    def read(self, n):
        '''read some bytes'''
        if len(self.buf) == 0:
            self._recv()
        if len(self.buf) > 0:
            if n > len(self.buf):
                n = len(self.buf)
            ret = self.buf[:n]
            self.buf = self.buf[n:]
            if self._debug >= 2:
                for b in ret:
                    self.debug("read 0x%x" % ord(b), 2)
            return ret
        return ''


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('command', metavar='CMD', nargs='?', default = None,
            help='Command to execute in the nsh')
    parser.add_argument("--port", "-p", dest="port",
                      help="Mavlink port name: udp: IP:PORT", default="udp:10.223.100.50:14550")
    args = parser.parse_args()

    mav_serialport = MavlinkSerialPort(args.port, 57600, devnum=10)
    # Send heartbeat so that mavlink-router will route data back to us
    mav_serialport.mav.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_GENERIC, 0, 0, 0)

    mav_serialport.write('\n\n\n') # make sure the shell is started
    mav_serialport.read(4096)

    mav_serialport.write(args.command + '\n')

    data = mav_serialport.read(4096)
    while data:
        if data and len(data) > 0:
            sys.stdout.write(data)
            sys.stdout.flush()
            data = mav_serialport.read(4096)

    mav_serialport.close()


if __name__ == '__main__':
    main()
