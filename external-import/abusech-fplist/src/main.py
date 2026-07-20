import traceback

from abusech_fplist_connector import ConnectorAbusechFplist, ConnectorSettings
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = ConnectorAbusechFplist(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
