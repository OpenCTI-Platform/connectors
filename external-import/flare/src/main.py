import sys
import traceback

import stix2
from connector import ConnectorSettings, FlareConnector
from connector.converter_to_stix import FlareToStixMapper
from flare_client import FlareClient
from pycti import Identity as PyctiIdentity
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        flare_client = FlareClient(
            helper=helper,
            api_key=settings.flare.api_key,
            base_url=settings.flare.api_base_url,
            tenant_id=settings.flare.tenant_id,
        )

        author_identity = stix2.Identity(
            id=PyctiIdentity.generate_id("Flare", "organization"),
            name="Flare",
            identity_class="organization",
            description="Cyber Threat Intelligence Platform",
            object_marking_refs=[stix2.TLP_WHITE.id],
        )
        mapper = FlareToStixMapper(config=settings, author_identity=author_identity)

        connector = FlareConnector(
            config=settings,
            helper=helper,
            flare_client=flare_client,
            mapper=mapper,
        )
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
