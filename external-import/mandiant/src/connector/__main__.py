import sys
import time

from connector.base import Mandiant

try:
    mandiantConnector = Mandiant()
    while True:
        mandiantConnector.run()
except Exception as err:
    print(err)
    time.sleep(10)
    sys.exit(0)
