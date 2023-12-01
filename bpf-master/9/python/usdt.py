from time import sleep

import stapsdt

provider = stapsdt.Provider("myprobe")
p1 = provider.add_probe("start", stapsdt.ArgTypes.int64)
p2 = provider.add_probe("ing", stapsdt.ArgTypes.int64)
p3 = provider.add_probe("end", stapsdt.ArgTypes.int64)
provider.load()

def my_end(value: int) -> int:
    if value > 0:
        p2.fire(value)
        print(value)
        return my_end(value-1)
    p3.fire(value)
    print("End")
    return value

def my_start(value: int) -> int:
    while True:
        p1.fire(value)
        print("Start")
        my_end(value)
        sleep(1)
    return value

if __name__ == '__main__':
    my_start(3)
