#!/bin/bash

apn="fast.t-mobile.com"

# mmcli -L
# /org/freedesktop/ModemManager1/Modem/0 [Sierra Wireless, Incorporated] RC7611

# Get the modem instance number wait until it is valid
while true; do
    modem_instance=$(mmcli -L | grep -oP '(?<=/Modem/)\d+')
    if [ -n "$modem_instance" ]; then
        break
    fi
    sleep 2
done
echo "Modem instance: $modem_instance"

# sudo mmcli -m 0 --simple-connect="apn=fast.t-mobile.com,ip-type=ipv4v6"
while true; do
    sudo mmcli -m $modem_instance --simple-connect="apn=$apn,ip-type=ipv4v6"
    if [ $? -eq 0 ]; then
        echo "Connected to APN $apn successfully."
        break
    else
        echo "Failed to connect to APN $apn."
    fi
    sleep 2
done

# Check the modem status
mmcli -m $modem_instance

# Get the bearer instance number. It will be the last Bearer/N number
bearer_instance=$(mmcli -m $modem_instance | grep -oP '(?<=/Bearer/)\d+$' | tail -n 1)
echo "Bearer instance: $bearer_instance"

# Connect the bearer instance
while true; do
    sudo mmcli -m $modem_instance --bearer=$bearer_instance
    if [ $? -eq 0 ]; then
        echo "Bearer $bearer_instance connected successfully."
        break
    else
        echo "Failed to connect bearer $bearer_instance."
    fi
    sleep 2
done

# Get the IPV4 address, prefix, gateway, DNS, and MTU values
# Will be in the format:
#   IPv4 configuration |         method: static
#                      |        address: XXX.XXX.XXX.XXX
#                      |         prefix: XX
#                      |        gateway: XXX.XXX.XXX.XXX
#                      |            dns: XXX.XXX.XXX.XXX, XXX.XXX.XXX.XXX
#                      |            mtu: XXX
ipv4_info=$(mmcli -m $modem_instance --bearer=$bearer_instance | grep -A 5 'IPv4 configuration')
ipv4_address=$(echo "$ipv4_info" | grep 'address' | awk '{print $3}')
ipv4_prefix=$(echo "$ipv4_info" | grep 'prefix' | awk '{print $3}')
ipv4_gateway=$(echo "$ipv4_info" | grep 'gateway' | awk '{print $3}')
ipv4_dns=$(echo "$ipv4_info" | grep 'dns' | awk '{print $3, $4}')
ipv4_mtu=$(echo "$ipv4_info" | grep 'mtu' | awk '{print $3}')

# Split the DNS values
IFS=', ' read -r dns1 dns2 <<< "$ipv4_dns"
# Remove ending comma from dns1
dns1=${dns1%,}

echo "IPv4 Address: $ipv4_address"
echo "IPv4 Prefix: $ipv4_prefix"
echo "IPv4 Gateway: $ipv4_gateway"
echo "IPv4 DNS1: $dns1"
echo "IPv4 DNS2: $dns2"
echo "IPv4 MTU: $ipv4_mtu"

# Flush existing IP address and routes
sudo ip addr flush dev wwan0
sudo ip route flush dev wwan0

sudo ip link set wwan0 up

# sudo ip addr add <address>/<prefix> dev wwan0
sudo ip addr add $ipv4_address/$ipv4_prefix dev wwan0
# sudo ip route add default via <gateway> dev wwan0 metric 4294967295
sudo ip route add default via $ipv4_gateway dev wwan0 metric 4294967295
# sudo ip link set wwan0 mtu <mtu>
sudo ip link set wwan0 mtu $ipv4_mtu

# Configure DNS
# sudo sh -c "echo 'nameserver XXX.XXX.XXX.XXX' >> /etc/resolv.conf"
# sudo sh -c "echo 'nameserver XXX.XXX.XXX.XXX' >> /etc/resolv.conf"
sudo sh -c "echo 'nameserver $dns1' >> /etc/resolv.conf"
sudo sh -c "echo 'nameserver $dns2' >> /etc/resolv.conf"

# Check the connection
ping -4 -c 4 -I wwan0 8.8.8.8
