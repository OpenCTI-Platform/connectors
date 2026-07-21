#!/usr/bin/env python3
"""Entry point for the OpenCTI -> Cloudflare Rules List stream connector (v2)."""

import traceback

from cloudflare_rules_list import Connector, ConnectorSettings
from cloudflare_rules_list.client import CloudflareRulesListClient
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        client = CloudflareRulesListClient(
            account_id=settings.cloudflare.account_id,
            api_token=settings.cloudflare.api_token.get_secret_value(),
            base_url=settings.cloudflare.api_base_url,
        )
        connector = Connector(helper=helper, config=settings, client=client)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
