#!/bin/bash
HOSTNAME="$(hostname -f).local"
PORT=5006

exec /usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/flight-review/app/serve.py --port=$PORT --address=0.0.0.0 --use-xheaders --allow-websocket-origin=$HOSTNAME --allow-websocket-origin=$HOSTNAME:$PORT
