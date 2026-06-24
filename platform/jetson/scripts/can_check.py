#!/usr/lib/ark-os/venv/bin/python3
'''
dump all messages in YAML format
'''

import dronecan, time, math

# get command line arguments
from argparse import ArgumentParser
parser = ArgumentParser(description='dump all DroneCAN messages')
parser.add_argument("--bitrate", default=1000000, type=int, help="CAN bit rate")
parser.add_argument("--node-id", default=100, type=int, help="CAN node ID")
parser.add_argument("--dna-server", action='store_true', default=False, help="run DNA server")
parser.add_argument("port", default=None, type=str, help="serial port")
args = parser.parse_args()

# Initializing a DroneCAN node instance.
node = dronecan.make_node(args.port, node_id=args.node_id, bitrate=args.bitrate)

# Initializing a node monitor, so we can see what nodes are online
node_monitor = dronecan.app.node_monitor.NodeMonitor(node)

if args.dna_server:
    # optionally start a DNA server
    dynamic_node_id_allocator = dronecan.app.dynamic_node_id.CentralizedServer(node, node_monitor)

# # callback for printing all messages in human-readable YAML format.
# node.add_handler(None, lambda msg: print(dronecan.to_yaml(msg)))

# make a callback to check for 100 valid messages. Timeout after 10 seconds
start_time = time.time()
count = 0

def count_messages(msg):
    global count

    count += 1

node.add_handler(None, count_messages)

while ((time.time() - start_time < 10) and (count < 100)):
    # Running the node until the application is terminated or until first error.
    try:
        node.spin(1)

    except:
        pass

print(f"received {count} messages")

if count >= 100:
    exit(0)

print("timeout")
exit(1)
