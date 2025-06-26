"""Dragos Connector for OpenCTI."""

import traceback
from datetime import timedelta
from logging import getLogger
from pathlib import Path

from dragos.adapters.config.env import ConfigLoaderEnv
from dragos.adapters.geocoding.octi import OctiGeocoding
from dragos.adapters.report.dragos_v1 import ReportsAPIV1
from dragos.app import Connector
from limiter import Limiter  # type: ignore[import-untyped]  # Limiter is not typed
from pycti import (  # type: ignore[import-untyped]  # PyCTI is not typed
    OpenCTIConnectorHelper,
)
from yarl import URL

logger = getLogger(__name__)

if __name__ == "__main__":
    try:
        dev_config = Path(__file__).parent / "config.yml"
        if dev_config.exists():
            from dragos.adapters.config.yaml import ConfigLoaderYAML

            logger.warning(
                "Using development config file. This should not be used for production."
            )
            config = ConfigLoaderYAML.from_yaml_path(config_path=dev_config)
        else:
            config = ConfigLoaderEnv()  # type: ignore[assignment]
            # both config are ConfigLoader abstract classes

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
            # bucket limiter set to 60 requests per minute
            # burst 60 then 1 new token per second
            rate_limiter=Limiter(
                rate=1,
                capacity=60,
                bucket="dragos",
            ),
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
