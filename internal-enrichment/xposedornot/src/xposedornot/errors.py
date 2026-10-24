class XposedOrNotError(Exception):
    """The XposedOrNot API could not be queried or answered with an error."""


class EnrichmentSkipped(Exception):
    """The observable is handed back untouched; the message says why."""


class EntityNotInScopeError(EnrichmentSkipped):
    """The entity type is not in the connector scope."""


class MaxTlpError(EnrichmentSkipped):
    """The observable's TLP exceeds the configured maximum."""


class InvalidEmailError(EnrichmentSkipped):
    """The observable value is not an email address."""


class EnrichmentError(Exception):
    """An enrichment failed; the message is already redacted."""
