"""CrowdStrikeActorDateRangeProvider."""

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from connectors_sdk.converters.crowdstrike.models import (
    CrowdStrikeActor,
    CrowdStrikeActorInput,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.providers.base import AbstractDateRangeProvider
from falconpy import Intel
from pydantic import ValidationError

ACTOR_SORT = "last_modified_date|asc"
ACTOR_FIELDS = "__full__"


class CrowdStrikeActorDateRangeProvider(
    AbstractDateRangeProvider[CrowdStrikeActorInput]
):
    """Return the CrowdStrike actors modified on or after a date, with their MITRE ids.

    The items are the input of ``CrowdStrikeActorConverter``. Each call makes one
    actor query, then one MITRE ATT&CK query per actor.
    """

    def __init__(self, client: Intel) -> None:
        """Initialize the provider.

        Args:
            client: An authenticated falconpy ``Intel`` client.
        """
        self.client = client

    def get_data(
        self, since: datetime, limit: int
    ) -> dict[datetime, list[CrowdStrikeActorInput]]:
        """Fetch the actors whose last modification date is on or after ``since``.

        Actors without a valid last modification date, or that do not match the
        expected format, are skipped and logged.

        Args:
            since: The timezone-aware start date, inclusive.
            limit: The maximum number of actors requested from CrowdStrike.

        Returns:
            The actors with their MITRE ATT&CK ids, keyed by last modification date (UTC).

        Raises:
            ValueError: If ``since`` is not timezone-aware.
            DataRetrievalError: If a CrowdStrike query fails.
        """
        if since.utcoffset() is None:
            raise ValueError("`since` must be timezone-aware.")

        # CrowdStrike dates are whole seconds, so truncating keeps the filter inclusive.
        actors = self._query(
            "actors",
            self.client.query_actor_entities,
            parameters={
                "limit": limit,
                "sort": ACTOR_SORT,
                "filter": f"last_modified_date:>={int(since.timestamp())}",
                "fields": ACTOR_FIELDS,
            },
        )

        results: dict[datetime, list[CrowdStrikeActorInput]] = {}
        for raw_actor in actors:
            parsed = self._parse_actor(raw_actor)
            if parsed is None:
                continue
            modified, actor = parsed
            mitre_attack_ids = self._query(
                f"MITRE ATT&CK of actor {actor.id}",
                self.client.query_mitre_attacks,
                id=str(actor.id),
            )
            results.setdefault(modified, []).append(
                CrowdStrikeActorInput(
                    actor=actor,
                    mitre_attack_ids=[
                        i for i in mitre_attack_ids if isinstance(i, str)
                    ],
                )
            )
        return results

    def _parse_actor(self, raw_actor: Any) -> tuple[datetime, CrowdStrikeActor] | None:
        """Read the last modification date and validate an actor.

        Args:
            raw_actor: One actor from the CrowdStrike response.

        Returns:
            The last modification date and the actor, or ``None`` if invalid.
        """
        actor_id = raw_actor.get("id") if isinstance(raw_actor, dict) else None
        try:
            modified = datetime.fromtimestamp(
                int(raw_actor["last_modified_date"]), tz=timezone.utc
            )
        except (KeyError, TypeError, ValueError, OverflowError, OSError):
            self.logger.warning(
                "Skipping CrowdStrike actor without a valid last modification date",
                meta={"actor_id": actor_id},
            )
            return None
        try:
            actor = CrowdStrikeActor.model_validate(raw_actor)
        except ValidationError as err:
            self.logger.warning(
                "Skipping CrowdStrike actor with an unexpected format",
                meta={"actor_id": actor_id, "error": str(err)},
            )
            return None
        return modified, actor

    def _query(
        self, description: str, query: Callable[..., Any], **kwargs: Any
    ) -> list[Any]:
        """Call a falconpy method and return the resources of its response.

        Args:
            description: What is queried, for error messages.
            query: The falconpy method.
            **kwargs: The method arguments.

        Returns:
            The ``resources`` of the response body, empty when absent.

        Raises:
            DataRetrievalError: If the call fails, or the response is not a 200.
        """
        try:
            response = query(**kwargs)
        except Exception as err:
            raise DataRetrievalError(f"Cannot query CrowdStrike {description}") from err
        if not isinstance(response, dict):
            raise DataRetrievalError(
                f"Unexpected CrowdStrike response for {description}"
            )
        status_code = response.get("status_code")
        if status_code != 200:
            raise DataRetrievalError(
                f"Cannot query CrowdStrike {description} (status {status_code})"
            )
        body = response.get("body")
        resources = body.get("resources") if isinstance(body, dict) else None
        if resources is None:
            return []
        if not isinstance(resources, list):
            raise DataRetrievalError(
                f"Unexpected CrowdStrike response for {description}"
            )
        return resources
