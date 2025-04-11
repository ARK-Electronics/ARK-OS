from jtop import jtop
import json
from datetime import datetime, timedelta

def convert(obj):
    if isinstance(obj, (datetime, timedelta)):
        return str(obj)
    return obj

with jtop() as jetson:
    while jetson.ok():
        # Convert datetime/timedelta to string, then pretty-print
        stats = {k: convert(v) for k, v in jetson.stats.items()}
        print(json.dumps(stats, indent=4))
