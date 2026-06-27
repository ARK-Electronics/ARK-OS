#!/usr/bin/env python3
"""Fake flight controller for the local test harness.

autopilot-manager listens on `udpin:localhost:14571` (it normally receives the FC feed
from mavlink-router). With no real autopilot we send a steady heartbeat plus a little
telemetry straight to that port, so the Autopilot page flips to "connected" and shows
moving values. This is the simplest possible stand-in — it does not answer parameter or
command requests; for that, point autopilot-manager at PX4 SITL instead.
"""
import math
import time

from pymavlink import mavutil

TARGET = "udpout:127.0.0.1:14571"


def main() -> None:
    mav = mavutil.mavlink_connection(TARGET, source_system=1, source_component=1)
    print(f"[mavlink-stub] sending heartbeats to {TARGET}", flush=True)

    t0 = time.time()
    while True:
        t = time.time() - t0

        mav.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_QUADROTOR,
            mavutil.mavlink.MAV_AUTOPILOT_PX4,
            mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED,
            0,
            mavutil.mavlink.MAV_STATE_STANDBY,
        )

        # Battery ~ slowly draining 16.8V -> shown on the UI.
        voltage_mv = int(16800 - (t * 2) % 4000)
        mav.mav.sys_status_send(
            0, 0, 0, 500, voltage_mv, -1, 78, 0, 0, 0, 0, 0, 0,
        )

        # A little motion so the page clearly isn't frozen.
        mav.mav.attitude_send(
            int(t * 1000),
            0.15 * math.sin(t),          # roll
            0.15 * math.cos(t),          # pitch
            (t * 0.2) % (2 * math.pi),   # yaw
            0.0, 0.0, 0.0,
        )
        mav.mav.global_position_int_send(
            int(t * 1000),
            int(47.3977 * 1e7), int(8.5456 * 1e7),  # Zurich-ish
            int((488 + 5 * math.sin(t)) * 1000),
            int(5 * math.sin(t) * 1000),
            0, 0, 0,
            int((t * 10) % 36000),
        )
        mav.mav.vfr_hud_send(
            5.0, 5.2, int((t * 2) % 360), 50, 488 + 5 * math.sin(t), 0.5 * math.cos(t),
        )

        time.sleep(0.5)


if __name__ == "__main__":
    main()
