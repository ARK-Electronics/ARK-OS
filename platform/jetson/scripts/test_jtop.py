from jtop import jtop

with jtop() as jetson:
    while jetson.ok():
        print(jetson.power)
        print("\n")
        print(jetson.temperature)
        print("\n")
        print(jetson.local_interfaces)
        print("\n")
        print(jetson.board)
        print("\n")
        print(jetson.nvpmodel)
        print("\n")
        print(jetson.jetson_clocks)






