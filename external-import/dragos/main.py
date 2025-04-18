"""Dragos Connector for OpenCTI."""
import traceback
from datetime import timedelta

from dragos.app import Connector
from dragos.adapters.config.env import ConfigLoaderEnv
from dragos.adapters.geocoding.octi import OctiGeocoding
from dragos.adapters.report.dragos_v1 import ReportsAPIV1
from pycti import OpenCTIConnectorHelper  # type: ignore[import-untyped]  # PyCTI is not typed

from yarl import URL

if __name__ == "__main__":
    try:
        config = ConfigLoaderEnv()
        config_dict = config.to_dict(token_as_plaintext=True)
        helper = OpenCTIConnectorHelper(config=config_dict)
        geocoding = OctiGeocoding(api_client=helper.api)
        reports = ReportsAPIV1(
            base_url=URL(str(config.dragos.api_base_url)),
            token=config.dragos.api_token,
            secret=config.dragos.api_secret,
            timeout=timedelta(seconds=30),
            retry=3,
            backoff=timedelta(seconds=1),
        )
        connector = Connector(
            config=config,
            helper=helper,
            reports=reports,
            geocoding=geocoding,
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
