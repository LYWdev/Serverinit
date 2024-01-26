from time import sleep

class sample:
    def end(self, value):
        if value > 0:
            print(value)
            return self.end(value-1)
        print("End")
        return value

    def start(self, value):
        while True:
           print("Start")
           self.end(value)
           sleep(1)

if __name__ == '__main__':
    sample().start(3)
