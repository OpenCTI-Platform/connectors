import sys
import time

from .base import Mandiant

try:
    mandiantConnector = Mandiant()
    while True:
        mandiantConnector.run()
except Exception:
    time.sleep(10)
    sys.exit(0)
