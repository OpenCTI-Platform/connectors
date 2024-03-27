import time

from malcore import Malcore

if __name__ == "__main__":
    try:
        connector = Malcore()
        connector.run()
    except:
        time.sleep(10)
        exit(0)
