import traceback

from connector.base import Mandiant

try:
    mandiantConnector = Mandiant()
    mandiantConnector.run()
except Exception:
    traceback.print_exc()
    exit(1)
