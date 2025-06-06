#!/bin/bash
HOSTNAME="$(hostname -f).local"
PORT=5006

exec python3 ~/.local/share/flight_review/app/serve.py --port=$PORT --address=0.0.0.0 --use-xheaders --allow-websocket-origin=$HOSTNAME --allow-websocket-origin=$HOSTNAME:$PORT
