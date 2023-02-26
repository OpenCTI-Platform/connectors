import sys
import time
import traceback

from misp import MISP

try:
    connector = MISP()
    connector.run()
except Exception:
    print(traceback.print_exc())
    time.sleep(10)
    sys.exit(0)
