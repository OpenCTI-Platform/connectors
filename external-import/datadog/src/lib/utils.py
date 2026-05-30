"""Utility functions for DataDog connector"""

CASE_INCIDENT_PRIORITIES = {
    "unknown": "P3",
    "info": "P4",
    "low": "P3",
    "medium": "P2",
    "high": "P1",
    "critical": "P0",
}


def normalize_csv_list(value) -> list[str]:
    """Normalise a config value into a ``list[str]``.

    ``pycti.get_config_variable`` returns whatever the underlying
    source produced: a Python ``list`` when the value came from the
    YAML config file (where the operator wrote it as a YAML list) or
    a raw ``str`` when the value came from the process environment
    (where multi-value config is conventionally comma-separated, e.g.
    ``DATADOG_ALERT_PRIORITIES="P1,P2"``). Callers that need to
    iterate over the values (membership checks, list comprehensions,
    joining into URL query strings) MUST first collapse both shapes
    into a list — otherwise the env-var path silently iterates the
    string character-by-character (e.g. ``[c for c in "P1,P2"]``
    yields ``["P", "1", ",", "P", "2"]``) and corrupts every
    downstream comparison.

    Contract:
      * ``None`` / ``""`` / whitespace-only inputs collapse to ``[]``
        so the caller does not need a separate empty-input guard.
      * Already-list inputs pass through after stripping each element
        and dropping empties, mirroring the env-var path so both
        sources behave identically.
      * ``str`` inputs split on commas, strip each element, and drop
        empties (a trailing comma like ``"P1,P2,"`` yields
        ``["P1", "P2"]``, not ``["P1", "P2", ""]``).
      * Any other type collapses to ``[]`` rather than raise — a
        misconfigured value should not crash startup, the connector's
        own validation surface should reject it instead.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []
