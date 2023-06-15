import sys
import time

from mandiant.base import Mandiant

try:
    mandiantConnector = Mandiant()
    while True:
        mandiantConnector.run()
except Exception as e:
    print(e)
    time.sleep(10)
    sys.exit(0)
