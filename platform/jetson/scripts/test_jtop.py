from jtop import jtop

with jtop() as jetson:
    while jetson.ok():
        print(jetson.json)
        print(jetson.power)
        print(jetson.temperature)
        print(jetson.local_interfaces)
        print(jetson.board)
        print(jetson.nvpmodel)
        print(jetson.jetson_clocks)






