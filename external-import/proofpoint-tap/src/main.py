import sys
import traceback

from proofpoint_tap import Connector, ConnectorSettings
from proofpoint_tap.adapters.campaign import CampaignsAPIV2
from proofpoint_tap.adapters.events import EventsAPIV2
from pycti import (  # type: ignore[import-untyped] # pycti does not provide stubs
    OpenCTIConnectorHelper,
)
from yarl import URL

if __name__ == "__main__":

    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        campaigns = CampaignsAPIV2(
            base_url=URL(str(settings.proofpoint_tap.api_base_url)),
            principal=settings.proofpoint_tap.api_principal_key,
            secret=settings.proofpoint_tap.api_secret_key,
            timeout=settings.proofpoint_tap.api_timeout,
            retry=settings.proofpoint_tap.api_retries,
            backoff=settings.proofpoint_tap.api_backoff,
        )
        events = EventsAPIV2(
            base_url=URL(str(settings.proofpoint_tap.api_base_url)),
            principal=settings.proofpoint_tap.api_principal_key,
            secret=settings.proofpoint_tap.api_secret_key,
            timeout=settings.proofpoint_tap.api_timeout,
            retry=settings.proofpoint_tap.api_retries,
            backoff=settings.proofpoint_tap.api_backoff,
        )

        connector = Connector(
            config=settings,
            helper=helper,
            campaigns=campaigns,
            events=events,
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
