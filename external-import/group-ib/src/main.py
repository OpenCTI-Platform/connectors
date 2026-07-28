from __future__ import annotations

import traceback
from typing import Any

import dotenv
from connector.connector import ExternalImportConnector
from connector.settings import ConfigConnector
from pipeline import collect_intelligence

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
        return collect_intelligence(
            helper=self.helper,
            collection=collection,
            ttl=ttl,
            event=event,
            mitre_mapper=mitre_mapper,
            config=config,
            flag_intrusion_set_instead_of_threat_actor=flag_intrusion_set_instead_of_threat_actor,
        )


if __name__ == "__main__":
    try:
        CustomConnector().run()
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
