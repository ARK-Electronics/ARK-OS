#!/bin/bash

# Check if the fan is working
# Usage: ./check_fan.sh [sudo_password]
# Returns: 0 on success, 1 on failure

# Get sudo password from argument or prompt
if [ -n "$1" ]; then
    SUDO_PASSWORD="$1"
else
    # If no password provided, try to use sudo without password
    SUDO_PASSWORD=""
fi

check_fan() {
    local fan_status=0
    
    # Check if fan hwmon device exists
    if [ -d /sys/devices/platform/pwm-fan/hwmon ]; then
        # Find the hwmon directory (usually hwmon0, hwmon1, etc.)
        local hwmon_dir=$(find /sys/devices/platform/pwm-fan/hwmon -name "hwmon[0-9]*" -type d | head -1)
        
        if [ -n "$hwmon_dir" ]; then
            # Check if PWM control file exists (Jetson uses PWM fan control, not RPM feedback)
            if [ -f "$hwmon_dir/pwm1" ]; then
                local pwm_value=$(cat "$hwmon_dir/pwm1" 2>/dev/null)
                echo "Fan PWM value: $pwm_value (0-255, where 0=off, 255=full speed)"
                
                if [ -n "$pwm_value" ] && [ "$pwm_value" -ge 0 ] && [ "$pwm_value" -le 255 ]; then
                    echo "Fan check PASSED - PWM fan control detected and accessible"
                    
                    local original_pwm="$pwm_value"
                    
                    # Check for RPM sensor (tachometer) - dynamically find the hwmon with rpm file
                    local rpm_file=""
                    local rpm_value=""
                    
                    # Search for rpm file in all hwmon devices
                    for hwmon_device in /sys/class/hwmon/hwmon*; do
                        if [ -f "$hwmon_device/rpm" ]; then
                            rpm_file="$hwmon_device/rpm"
                            echo "Found RPM sensor at: $rpm_file"
                            break
                        fi
                    done
                    
                    if [ -n "$rpm_file" ] && [ -f "$rpm_file" ]; then
                        # Set fan to 100% speed first to get a reliable RPM reading
                        echo "Setting fan to 100% speed for initial RPM check..."
                        
                        # Use sudo with password if provided, otherwise try without password
                        if [ -n "$SUDO_PASSWORD" ]; then
                            sudo_cmd="echo \"$SUDO_PASSWORD\" | sudo -S"
                        else
                            sudo_cmd="sudo"
                        fi
                        
                        if eval "$sudo_cmd bash -c \"echo 255 > $hwmon_dir/pwm1\"" 2>/dev/null; then
                            sleep 3  # Wait for fan speed to stabilize at 100%
                            echo "Fan set to 100% PWM (255)"
                        else
                            echo "Failed to set fan to 100% - insufficient privileges"
                            fan_status=1
                            return $fan_status
                        fi
                        
                        rpm_value=$(cat "$rpm_file" 2>/dev/null)
                        if [ -n "$rpm_value" ]; then
                            echo "Current fan RPM at 100% speed: $rpm_value"
                            
                            # Critical check: RPM must be > 0 for fan to be considered working
                            if [ "$rpm_value" -eq 0 ]; then
                                echo "CRITICAL FAILURE: Fan RPM is 0 at 100% speed - Fan may be unplugged or broken!"
                                fan_status=1
                                return $fan_status
                            elif [ "$rpm_value" -lt 500 ]; then
                                echo "WARNING: Fan RPM is very low ($rpm_value) at 100% speed - possible hardware issue"
                            fi
                        else
                            echo "FAILURE: Cannot read RPM sensor"
                            fan_status=1
                            return $fan_status
                        fi
                    else
                        echo "FAILURE: RPM sensor not found"
                        fan_status=1
                        return $fan_status
                    fi
                    
                    # Comprehensive fan test: Ramp DOWN -> Verify RPM decreases -> Ramp UP -> Verify RPM increases
                    echo "=== Starting comprehensive fan test ==="
                    
                    # Step 1: Ramp down fan speed and verify RPM decreases
                    echo "Step 1: Ramping down fan speed..."
                    local previous_rpm="$rpm_value"
                    local pwm_levels=(128 32)  # Ramp down: 50%, 12.5%
                    
                    for pwm_level in "${pwm_levels[@]}"; do
                        echo "Setting PWM to $pwm_level ($(( pwm_level * 100 / 255 ))% speed)..."
                        
                        # Use sudo with password if provided, otherwise try without password
                        if [ -n "$SUDO_PASSWORD" ]; then
                            sudo_cmd="echo \"$SUDO_PASSWORD\" | sudo -S"
                        else
                            sudo_cmd="sudo"
                        fi
                        
                        if eval "$sudo_cmd bash -c \"echo $pwm_level > $hwmon_dir/pwm1\"" 2>/dev/null; then
                            sleep 3  # Wait for fan speed to stabilize
                            local current_pwm=$(cat "$hwmon_dir/pwm1" 2>/dev/null)
                            echo "PWM set to: $current_pwm"
                            
                            # Check RPM at this level
                            if [ -f "$rpm_file" ]; then
                                local current_rpm=$(cat "$rpm_file" 2>/dev/null)
                                echo "Current RPM: $current_rpm (previous: $previous_rpm)"
                                
                                if [ -n "$current_rpm" ] && [ -n "$previous_rpm" ]; then
                                    # Critical check: RPM must always be > 0 during operation
                                    if [ "$current_rpm" -eq 0 ]; then
                                        echo "✗ CRITICAL FAILURE: RPM dropped to 0 - Fan disconnected or failed!"
                                        fan_status=1
                                        break
                                    fi
                                    
                                    if [ "$current_rpm" -lt "$previous_rpm" ]; then
                                        echo "✓ RPM decreased: $previous_rpm -> $current_rpm"
                                    elif [ "$current_rpm" -eq "$previous_rpm" ]; then
                                        echo "→ RPM stable: $current_rpm (thermal management may be limiting)"
                                    else
                                        echo "✗ RPM increased unexpectedly: $previous_rpm -> $current_rpm"
                                    fi
                                    previous_rpm="$current_rpm"
                                else
                                    echo "✗ FAILURE: Cannot read RPM values"
                                    fan_status=1
                                    break
                                fi
                            fi
                        else
                            echo "Failed to set PWM to $pwm_level - insufficient privileges"
                            fan_status=1
                            break
                        fi
                    done

                    echo "Ramp down test completed"

                    # Step 2: Ramp up fan speed and verify RPM increases
                    echo "Step 2: Ramping up fan speed..."
                    local ramp_up_levels=(128 255)  # Ramp up: 50%, 100%
                    
                    for pwm_level in "${ramp_up_levels[@]}"; do
                        echo "Setting PWM to $pwm_level ($(( pwm_level * 100 / 255 ))% speed)..."
                        
                        # Use sudo with password if provided, otherwise try without password
                        if [ -n "$SUDO_PASSWORD" ]; then
                            sudo_cmd="echo \"$SUDO_PASSWORD\" | sudo -S"
                        else
                            sudo_cmd="sudo"
                        fi
                        
                        if eval "$sudo_cmd bash -c \"echo $pwm_level > $hwmon_dir/pwm1\"" 2>/dev/null; then
                            sleep 3  # Wait for fan speed to stabilize
                            local current_pwm=$(cat "$hwmon_dir/pwm1" 2>/dev/null)
                            echo "PWM set to: $current_pwm"

                            # Check RPM at this level
                            if [ -f "$rpm_file" ]; then
                                local current_rpm=$(cat "$rpm_file" 2>/dev/null)
                                echo "Current RPM: $current_rpm (previous: $previous_rpm)"

                                if [ -n "$current_rpm" ] && [ -n "$previous_rpm" ]; then
                                    # Critical check: RPM must always be > 0 during operation
                                    if [ "$current_rpm" -eq 0 ]; then
                                        echo "✗ CRITICAL FAILURE: RPM dropped to 0 - Fan disconnected or failed!"
                                        fan_status=1
                                        break
                                    fi
                                    
                                    if [ "$current_rpm" -gt "$previous_rpm" ]; then
                                        echo "✓ RPM increased: $previous_rpm -> $current_rpm"
                                    elif [ "$current_rpm" -eq "$previous_rpm" ]; then
                                        echo "→ RPM stable: $current_rpm (may have reached thermal limit)"
                                    else
                                        echo "✗ RPM decreased unexpectedly: $previous_rpm -> $current_rpm"
                                    fi
                                    previous_rpm="$current_rpm"
                                else
                                    echo "✗ FAILURE: Cannot read RPM values"
                                    fan_status=1
                                    break
                                fi
                                
                                # Special check for maximum speed
                                if [ "$pwm_level" -eq 255 ]; then
                                    if [ "$current_rpm" -gt 1000 ]; then
                                        echo "Maximum speed test PASSED - Fan at high RPM: $current_rpm"
                                    elif [ "$current_rpm" -gt 0 ]; then
                                        echo "Maximum speed test WARNING - Fan RPM is $current_rpm (may be thermally limited)"
                                    else
                                        echo "Maximum speed test FAILED - Fan RPM is 0, fan disconnected!"
                                        fan_status=1
                                    fi
                                fi
                            fi
                        else
                            echo "Failed to set PWM to $pwm_level - insufficient privileges"
                            fan_status=1
                            break
                        fi
                    done
                    
                    echo "Ramp up test completed"
                    
                    # Step 3: Restore original PWM value
                    echo "Step 3: Restoring original fan speed..."
                    
                    # Use sudo with password if provided, otherwise try without password
                    if [ -n "$SUDO_PASSWORD" ]; then
                        sudo_cmd="echo \"$SUDO_PASSWORD\" | sudo -S"
                    else
                        sudo_cmd="sudo"
                    fi
                    
                    if eval "$sudo_cmd bash -c \"echo $original_pwm > $hwmon_dir/pwm1\"" 2>/dev/null; then
                        sleep 2
                        local restored_pwm=$(cat "$hwmon_dir/pwm1" 2>/dev/null)
                        echo "Fan restored to original PWM: $restored_pwm"
                    fi

                    echo "=== Comprehensive fan test completed ==="

                    # Test write permissions for future control
                    if [ -w "$hwmon_dir/pwm1" ]; then
                        echo "Fan control is writable - fan can be controlled directly"
                    else
                        echo "Fan control requires root privileges for modification"
                    fi
                else
                    echo "Fan check FAILED - Invalid PWM value: $pwm_value"
                    fan_status=1
                fi
            else
                echo "Fan check FAILED - PWM control file not found"
                fan_status=1
            fi
        else
            echo "Fan check FAILED - hwmon directory not found"
            fan_status=1
        fi
    else
        echo "Fan check FAILED - PWM fan device not found"
        fan_status=1
    fi
    
    return $fan_status
}

# Run the fan check
check_fan
exit $?