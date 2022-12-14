import sys
import time

from mandiant import Mandiant

try:
    mandiantConnector = Mandiant()
    mandiantConnector.run()
except Exception as e:
    print(e)
    time.sleep(10)
    sys.exit(0)
