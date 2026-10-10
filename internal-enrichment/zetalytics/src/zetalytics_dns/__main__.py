"""Entry point for the Zetalytics DNS connector."""

import os
import sys
import traceback


def main() -> None:
    try:
        from pycti import OpenCTIConnectorHelper
        from zetalytics_dns.client import ZetalyticsClient
        from zetalytics_dns.connector import Connector
        from zetalytics_dns.settings import ConfigLoader

        config = ConfigLoader()  # type: ignore[call-arg]

        # pycti's OpenCTIConnectorHelper resolves CONNECTOR_NAME via
        # get_config_variable(), which checks the raw environment variable
        # *before* the config dict we pass in. Without this, it would silently
        # ignore ConfigLoader's lookback-suffixed name (e.g. "Zetalytics DNS -
        # Deep Investigation (2 years)") and register the connector in OpenCTI
        # using whatever CONNECTOR_NAME is set to in the environment/compose
        # file. Sync it here, before constructing the helper, so OpenCTI shows
        # the correct name.
        os.environ["CONNECTOR_NAME"] = config.connector.name

        helper = OpenCTIConnectorHelper(
            config=config.to_helper_config(),
            playbook_compatible=True,
        )
        client = ZetalyticsClient(
            token=config.zetalytics.token.get_secret_value(),
            request_timeout=config.zetalytics.request_timeout,
        )
        connector = Connector(config=config, helper=helper, client=client)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
