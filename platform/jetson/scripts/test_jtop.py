from jtop import jtop
import json

with jtop() as jetson:
    # jetson.ok() will provide the proper update frequency
    while jetson.ok():
        # Read tegra stats
        json.dumps(print(jetson.stats))
