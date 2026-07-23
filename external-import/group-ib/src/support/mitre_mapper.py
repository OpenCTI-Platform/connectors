from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ciaops.decorators import cache_data
from connector.settings import ConfigConnector

if TYPE_CHECKING:
    from ciaops.adapters.opencti_adapter import TIAdapter


@cache_data(
    cache_dir=ConfigConnector.MITRE_CACHE_FOLDER,
    cache_file=ConfigConnector.MITRE_CACHE_FILENAME,
    ttl=1,
)
def get_mitre_mapper(adapter: TIAdapter, helper: Any) -> dict[str, str]:
    helper.connector_logger.info("MITRE mapper: loading via TIPoller")
    poller = adapter._set_up_poller()
    try:
        mitre_mapper = poller.get_mitre_attack_pattern_map()
    finally:
        poller.close_session()
    helper.connector_logger.info("MITRE mapper: %s attack patterns", len(mitre_mapper))
    return mitre_mapper
