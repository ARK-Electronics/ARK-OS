from jtop import jtop

with jtop() as jetson:
    # jetson.ok() will provide the proper update frequency
    while jetson.ok():
        # Read tegra stats
        print(jetson.stats)
