#!/bin/bash

# Check the Jetson fan: confirm it is connected, spins up, and HOLDS full speed for a few seconds (so a
# shoddy fan that flashes then seizes is caught, not just one that never starts).
# Usage: ./check_fan.sh [sudo_password]   (run as root, e.g. the bench's sudo, or pass the password to self-sudo)
# Returns: 0 on success, 1 on failure
#
# The pwm-fan driver has a thermal governor (cooling_device type=pwm-fan) that rewrites pwm1 on its own
# ~1s cycle, so a single commanded speed only holds for the spin-up transient before the governor reasserts
# a thermally-chosen value (and when the Jetson is cool it parks the fan at 0, so an idle RPM read proves
# nothing). To hold the fan at full we re-write pwm1 every tick, faster than the governor reasserts, and
# require RPM to stay above MIN_RPM across the sustain window. ~3.8s, versus the old ramp test's 17s of
# stabilisation sleeps that only ever sampled governor-reasserted noise.

MIN_RPM=3000         # a healthy fan holds ~5000 at full; governor steady is ~2000, so this cleanly separates them
SPINUP_SAMPLES=4     # ~0.8s of spin-up ramp — driven but not graded
SUSTAIN_SAMPLES=15   # ~3s that must stay >= MIN_RPM
INTERVAL=0.2         # re-write faster than the governor's ~1s reassert

SUDO_PASSWORD="$1"

write_pwm() {  # write $1 to pwm1 as root: direct when already root, else sudo (-S with the password arg if given)
    if [ "$(id -u)" -eq 0 ]; then
        echo "$1" > "$PWM" 2>/dev/null
    elif [ -n "$SUDO_PASSWORD" ]; then
        echo "$SUDO_PASSWORD" | sudo -S bash -c "echo $1 > $PWM" 2>/dev/null
    else
        sudo bash -c "echo $1 > $PWM" 2>/dev/null
    fi
}

pwm_dir=$(find /sys/devices/platform/pwm-fan/hwmon -name 'hwmon[0-9]*' -type d 2>/dev/null | head -1)
PWM="$pwm_dir/pwm1"
RPM=""
for hwmon_device in /sys/class/hwmon/hwmon*; do
    [ -f "$hwmon_device/rpm" ] && { RPM="$hwmon_device/rpm"; break; }
done
[ -f "$PWM" ] || { echo "fan: FAILED: no pwm-fan device"; exit 1; }
[ -n "$RPM" ] || { echo "fan: FAILED: no rpm sensor"; exit 1; }

original_pwm=$(cat "$PWM")

# Spin up, then hold at full (re-writing each tick to outpace the governor) and watch RPM stay high.
peak_rpm=0
min_sustained_rpm=99999
for sample in $(seq 1 $((SPINUP_SAMPLES + SUSTAIN_SAMPLES))); do
    write_pwm 255 || { echo "fan: FAILED: cannot set pwm (privileges)"; exit 1; }
    rpm=$(cat "$RPM" 2>/dev/null); rpm=${rpm:-0}
    [ "$rpm" -gt "$peak_rpm" ] && peak_rpm="$rpm"
    [ "$sample" -gt "$SPINUP_SAMPLES" ] && [ "$rpm" -lt "$min_sustained_rpm" ] && min_sustained_rpm="$rpm"
    sleep "$INTERVAL"
done

# Hand the fan back to the governor (it reasserts within ~1s regardless).
write_pwm "$original_pwm"

echo "Fan RPM at full speed: peak $peak_rpm, sustained min $min_sustained_rpm (threshold $MIN_RPM)"
if [ "$min_sustained_rpm" -ge "$MIN_RPM" ]; then
    echo "fan: OK"
    exit 0
fi
echo "fan: FAILED: fan did not hold full speed (min ${min_sustained_rpm} rpm < ${MIN_RPM})"
exit 1
