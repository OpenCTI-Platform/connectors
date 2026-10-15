from __future__ import annotations

import traceback
from typing import Any

import dotenv
from connector.connector import ExternalImportConnector
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConfigConnector, ConnectorSettings
from pycti import OpenCTIConnectorHelper

# TODO(manager-supported blocker) [minor]: the sdk settings loader already reads
# ``.env`` by itself (only when no ``config.yml`` exists). This extra
# ``load_dotenv()`` exports ``.env`` into ``os.environ``, and environment
# variables outrank ``config.yml`` in the sdk precedence (env > yaml > default),
# so a stray ``.env`` silently overrides ``config.yml`` - the opposite of what
# the README promises ("config.yml wins"). Kept as-is to preserve behaviour.
dotenv.load_dotenv()


class CustomConnector(ExternalImportConnector):
    def _collect_intelligence(
        self,
        collection: str,
        ttl: int | None,
        event: dict[str, Any],
        mitre_mapper: dict[str, str],
        config: ConfigConnector,
        flag_intrusion_set_instead_of_threat_actor: bool = False,
    ) -> list[Any]:
        converter = ConverterToStix(helper=self.helper, config=config)
        return converter.convert_event(
            collection=collection,
            event=event,
            mitre_mapper=mitre_mapper,
            ttl=ttl,
            flag_intrusion_set_instead_of_threat_actor=(
                flag_intrusion_set_instead_of_threat_actor
            ),
        )


if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        CustomConnector(settings=settings, helper=helper).run()
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
