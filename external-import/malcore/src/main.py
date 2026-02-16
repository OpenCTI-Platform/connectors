import sys
import traceback

from malcore import Malcore

if __name__ == "__main__":
    try:
        connector = Malcore()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
