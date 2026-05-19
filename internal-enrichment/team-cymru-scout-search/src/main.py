import traceback

from pycti import OpenCTIConnectorHelper
from scout_search_connector import ConnectorSettings, ScoutSearchConnectorConnector
from scout_search_connector.setup_pattern_type import setup_vocabulary

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(), playbook_compatible=True
        )

        setup_vocabulary(
            helper,
            settings.pure_signal_scout.indicator_pattern_type,
            settings.pure_signal_scout.pattern_description,
        )

        connector = ScoutSearchConnectorConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
