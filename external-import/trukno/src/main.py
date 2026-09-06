import sys
import traceback

from trukno_connector.runtime import main
from trukno_connector.settings import ConnectorSettings

__all__ = ["ConnectorSettings", "main"]

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
