"""Dragos Connector for OpenCTI."""

import traceback
from datetime import timedelta
from logging import getLogger

from dragos.adapters.geocoding.octi import OctiGeocoding
from dragos.adapters.report.dragos_v1 import ReportsAPIV1
from dragos.connector import Connector
from dragos.settings import ConnectorSettings
from limiter import Limiter  # type: ignore[import-untyped]  # Limiter is not typed
from pycti import (  # type: ignore[import-untyped]  # PyCTI is not typed
    OpenCTIConnectorHelper,
)
from yarl import URL

logger = getLogger(__name__)

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        geocoding = OctiGeocoding(api_client=helper.api)
        reports = ReportsAPIV1(
            base_url=URL(str(settings.dragos.api_base_url)),
            token=settings.dragos.api_token,
            secret=settings.dragos.api_secret,
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
            config=settings,
            helper=helper,
            reports=reports,
            geocoding=geocoding,
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
