"""Lookup of CrowdStrike Falcon Intelligence actors by the name indicators use."""

import json
import logging
from typing import Any, Protocol

from crowdstrike_indicators.entities.models import CrowdStrikeActor
from crowdstrike_indicators.extract.api import response_body
from pydantic import ValidationError

from shared.enricher import AbstractEnricher

LOGGER = logging.getLogger(__name__)

# Exactly what the existing connector packs into its Intrusion Sets, plus
# ``slug`` for matching. Never a collection such as ``__full__``.
ACTOR_FIELDS = (
    "id",
    "name",
    "slug",
    "url",
    "known_as",
    "description",
    "short_description",
    "first_activity_date",
    "last_activity_date",
    "motivations",
    "objectives",
    "actor_type",
)
# Same bound as the existing connector. A name filter returns very few
# actors: this only bounds a surprise.
ACTOR_QUERY_LIMIT = 100


class ActorsClient(Protocol):
    """The part of FalconPy's ``Intel`` service class the enricher uses.

    ``query_actor_entities`` is the ``QueryIntelActorEntities`` operation
    (``GET /intel/combined/actors/v1``). It returns FalconPy's response dict:
    ``{"status_code": ..., "headers": ..., "body": ...}``.
    """

    def query_actor_entities(self, **kwargs: Any) -> dict[str, Any]: ...


def normalize(value: str) -> str:
    """Return the form a name, a slug and a token are compared in.

    Indicators name actors with tokens such as ``SALTYSPIDER``, while the
    actors API returns ``SALTY SPIDER`` and ``salty-spider``. This rule is
    provisional until confirmed against the real API.
    """
    return value.upper().replace(" ", "").replace("-", "")


def name_filter(token: str) -> str:
    """Return the FQL filter looking an actor up by name."""
    escaped = token.replace("\\", "\\\\").replace("'", "\\'")
    return f"name:'{escaped}'"


class CrowdStrikeActorEnricher(AbstractEnricher[CrowdStrikeActor]):
    """Resolve an actor token, such as ``SALTYSPIDER``, into its actor.

    Each uncached token costs one actors request. The first actor of the
    response whose normalized ``name`` or ``slug`` equals the normalized
    token is returned; with none, the token resolves to ``None``. There is
    no fallback to another actor of the response. Actors failing validation
    are logged and skipped.
    """

    def __init__(self, client: ActorsClient) -> None:
        super().__init__()
        self.client = client

    def _fetch(self, key: str) -> CrowdStrikeActor | None:
        """Look ``key`` up through the actors API.

        :raises CrowdStrikeAPIError: when the API answers with an error.
        """
        response = self.client.query_actor_entities(
            filter=name_filter(key),
            fields=list(ACTOR_FIELDS),
            limit=ACTOR_QUERY_LIMIT,
        )
        resources = response_body(response).get("resources") or []
        wanted = normalize(key)
        for raw in resources:
            actor = self._validate(key, raw)
            if actor is None:
                continue
            if normalize(actor.name) == wanted or (
                actor.slug is not None and normalize(actor.slug) == wanted
            ):
                return actor
        return None

    @staticmethod
    def _validate(key: str, raw: Any) -> CrowdStrikeActor | None:
        try:
            return CrowdStrikeActor.model_validate(raw)
        except ValidationError as error:
            LOGGER.warning(
                "Skipping an invalid actor returned for %s: %s; raw actor: %s",
                key,
                json.dumps(json.loads(error.json(include_url=False))),
                json.dumps(raw, default=str),
            )
            return None
