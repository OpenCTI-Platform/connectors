import traceback

from helpers import SilentPushConnectorHelper

if __name__ == "__main__":
    try:
        connector = SilentPushConnectorHelper()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
