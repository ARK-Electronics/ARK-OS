from jtop import jtop

with jtop() as jetson:
    while jetson.ok():
        # print(jetson.stats)
        print(jetson.power)

