"""Exceptions of internal enrichment connectors.

Raised while handling an enrichment message, they tell ``InternalEnrichmentConnector``
that the entity is skipped instead of enriched, or that the message is invalid.
"""


class UnsupportedEntityError(Exception):
    """Raised when a connector does not enrich an entity it received.

    For example, the entity type is out of the connector scope, the entity TLP is not
    allowed by the connector max TLP, or no processor supports the entity. This is not
    a failure: the connector skips the entity on purpose. The internal enrichment
    connector completes the work with the error message.
    """


class InvalidEnrichmentMessageError(Exception):
    """Raised when the message data passed by pycti is not a valid enrichment message.

    The ``pydantic.ValidationError`` is its cause. It tells an invalid message apart
    from a ``ValidationError`` raised later by a processor (e.g. an SDK model built
    with an invalid value). The internal enrichment connector puts the work in error.
    """
