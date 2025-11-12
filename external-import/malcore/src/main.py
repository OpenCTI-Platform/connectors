import time

from malcore import Malcore

if __name__ == "__main__":
    try:
        connector = Malcore()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
