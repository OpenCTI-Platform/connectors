import sys
import time
import traceback

from .base import Mandiant

try:
    mandiantConnector = Mandiant()
    while True:
        mandiantConnector.run()
except Exception as e:
    print(traceback.format_exc())
    time.sleep(10)
    sys.exit(0)
