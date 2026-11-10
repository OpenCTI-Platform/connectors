"""PolySwarm live hunting source (interface placeholder)."""

from typing import Any


class HuntingSource:
    """Collect PolySwarm live hunting results as STIX objects."""

    def __init__(
        self,
        config: Any,
        author: dict[str, Any],
        tlp_marking: dict[str, Any],
        logger: Any,
        client: Any = None,
    ) -> None:
        self.config = config
        self.author = author
        self.tlp_marking = tlp_marking
        self.logger = logger
        self.client = client

    def collect(self, state: dict) -> tuple[list[dict], dict]:
        """Return (STIX 2.1 objects as plain dicts, the updated hunting sub-state).

        `state` is state.get("hunting", {}); the connector stores the returned
        dict back under "hunting". Objects carry created_by_ref=author["id"] and
        object_marking_refs=[tlp_marking["id"]].
        """
        raise NotImplementedError
