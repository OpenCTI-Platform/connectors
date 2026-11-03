"""Entry point of the Elastic Security hunt connector."""

import traceback

from elastic_security_hunt import ConnectorSettings, ElasticSecurityHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ElasticSecurityHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
