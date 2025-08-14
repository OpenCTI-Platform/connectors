import sys
import traceback

from pycti import OpenCTIConnectorHelper
from threatmatch.config import ConnectorSettings
from threatmatch.connector import Connector
from threatmatch.converter import Converter


def main() -> None:
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.model_dump_pycti())
    converter = Converter(
        helper=helper,
        author_name="Security Alliance",
        author_description="Security Alliance is a cyber threat intelligence product and services company, formed in 2007.",
        tlp_level=config.threatmatch.tlp_level,
        threat_actor_to_intrusion_set=config.threatmatch.threat_actor_as_intrusion_set,
    )

    connector = Connector(helper=helper, config=config, converter=converter)
    connector.run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
