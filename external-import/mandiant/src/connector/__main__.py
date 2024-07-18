import traceback

from connector.base import Mandiant

try:
    mandiantConnector = Mandiant()
    while True:
        mandiantConnector.run()
except Exception:
    traceback.print_exc()
    exit(1)
