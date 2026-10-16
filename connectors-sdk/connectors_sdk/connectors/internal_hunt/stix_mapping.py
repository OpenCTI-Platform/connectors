"""STIX mapping of telemetry hunt results.

For a run with hits, the bundle holds the IOC observables extracted from the
results, restricted to the observable types the hunt expects, and one
``observed-data`` per observable, with the number of result events holding it.

No sighting is sent: OpenCTI keeps one sighting per hunt, sighted technique or
indicator and Security Platform, and updates it in place when it finalizes a
run, counting the distinct hits it knows from the ``hit_keys`` of the runs. A
sighting per run would have its identifier derived from the event bounds of the
run, so every run would create a new one and overlapping windows would count
the same events again.

Every object inherits the markings and the author of the hunt. Identifiers are
deterministic: observables keep their standard identifiers, while observed-data
carry the hunt run and have identifiers scoped to it, so a retry of a run
upserts its own objects and two runs never share one.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from connectors_sdk.connectors.internal_hunt.models import HuntRequest
from connectors_sdk.connectors.internal_hunt.observables import (
    ObservableValue,
    to_observable_model,
)
from connectors_sdk.models import (
    BaseIdentifiedEntity,
    ObservedData,
    Reference,
    TLPMarking,
)


def hunt_author(request: HuntRequest) -> Reference | None:
    """Return the author of the hunt as a reference, if any."""
    created_by = request.hunt.created_by_ref
    return Reference(id=created_by) if created_by else None


def hunt_markings(request: HuntRequest) -> list[TLPMarking | Reference]:
    """Return the markings of the hunt as references."""
    return [Reference(id=marking) for marking in request.hunt.object_marking_refs]


def build_observed_data(
    request: HuntRequest,
    observations: Sequence[tuple[BaseIdentifiedEntity, int]],
    first_seen: datetime,
    last_seen: datetime,
) -> list[ObservedData]:
    """Build the observed-data of the observables found by a hunt run.

    One observed-data per observable, the most observed first, its
    ``number_observed`` being the observations of that observable. Its
    identifier derives from the hunt run and the observable only, so a retry
    of the run upserts the same observed-data whatever the counts it sees.

    Args:
        request: The hunt run request.
        observations: The observables found, each with its number of
            observations (at least one).
        first_seen: Time of the first observation of the run.
        last_seen: Time of the last observation of the run.

    Returns:
        The observed-data, stamped with the hunt run (empty without observable).
    """
    author = hunt_author(request)
    markings = hunt_markings(request) or None
    return [
        ObservedData(
            first_observed=first_seen,
            last_observed=last_seen,
            number_observed=count,
            entities=[entity],
            hunt_run_id=request.hunt_run.id,
            author=author,
            markings=markings,
        )
        for entity, count in sorted(observations, key=lambda item: -item[1])
    ]


def build_telemetry_objects(
    request: HuntRequest,
    hits_count: int,
    first_seen: datetime,
    last_seen: datetime,
    observables: Sequence[ObservableValue],
) -> list[BaseIdentifiedEntity]:
    """Build the knowledge produced by a telemetry hunt run: its observables and their observed-data.

    The sightings of the techniques and indicators of the hunt are kept by
    OpenCTI, one per Security Platform, from the ``hit_keys`` of the runs.

    Args:
        request: The hunt run request.
        hits_count: Number of hits of the run (after benign suppression).
        first_seen: Time of the first matching event.
        last_seen: Time of the last matching event.
        observables: Observables extracted from the results.

    Returns:
        The connectors-sdk models to send to OpenCTI (empty without hits).
    """
    if hits_count <= 0:
        return []
    author = hunt_author(request)
    markings = hunt_markings(request)
    observable_models: list[BaseIdentifiedEntity] = [
        to_observable_model(observable, author, markings) for observable in observables
    ]
    return [
        *observable_models,
        *build_observed_data(
            request,
            [
                (model, observable.count)
                for model, observable in zip(
                    observable_models, observables, strict=True
                )
            ],
            first_seen,
            last_seen,
        ),
    ]
