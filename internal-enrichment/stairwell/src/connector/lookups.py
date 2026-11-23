from __future__ import annotations

from typing import Any, Callable

from connector.stairwell import StairwellAPIError
from connectors_sdk.exceptions.error import DataRetrievalError


def optional_lookup(
    helper: Any, lookup: str, call: Callable[..., Any], *args: Any, **kwargs: Any
) -> Any:
    """Run a Stairwell lookup the enrichment can do without.

    A failed request is logged as a warning and returns None, so the
    enrichment goes on with what the other lookups returned. Anything other
    than a Stairwell request failure propagates.
    """
    try:
        return call(*args, **kwargs)
    except StairwellAPIError as err:
        helper.connector_logger.warning(
            "Stairwell lookup failed; enriching without it",
            meta={"lookup": lookup, "status": err.status, "error": str(err)},
        )
        return None


def lookup_all(
    helper: Any, subject: str, lookups: dict[str, Callable[[], Any]]
) -> dict[str, Any] | None:
    """Run lookups that each contribute part of one enrichment.

    Returns each lookup's result by name (None where it found nothing or
    failed), or None when every lookup found nothing. A failed lookup is
    logged as a warning while another one still returns data; when none
    does and at least one failed, `DataRetrievalError` is raised from the
    first failure.
    """
    results: dict[str, Any] = {}
    failures: list[tuple[str, StairwellAPIError]] = []
    for name, call in lookups.items():
        try:
            results[name] = call()
        except StairwellAPIError as err:
            results[name] = None
            failures.append((name, err))
    if not any(result is not None for result in results.values()):
        if failures:
            names = ", ".join(
                f"{name} ({err.status if err.status is not None else 'no response'})"
                for name, err in failures
            )
            raise DataRetrievalError(
                f"Every Stairwell request for {subject} failed or found nothing "
                f"(failed: {names})"
            ) from failures[0][1]
        return None
    for name, err in failures:
        helper.connector_logger.warning(
            "Stairwell lookup failed; enriching without it",
            meta={
                "subject": subject,
                "lookup": name,
                "status": err.status,
                "error": str(err),
            },
        )
    return results
