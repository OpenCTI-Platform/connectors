"""Exceptions of internal enrichment connectors.

Raised while handling an enrichment message, they tell ``InternalEnrichmentConnector``
that the entity is skipped instead of enriched.
"""


class UnsupportedEntityError(Exception):
    """Raised when a connector does not enrich an entity it received.

    For example, the entity TLP is not allowed by the connector max TLP, or no processor
    supports the entity. This is not a failure: the connector skips the entity on purpose.
    The internal enrichment connector completes the work with the error message.
    """


class EntityOutOfScopeError(UnsupportedEntityError):
    """Raised when the entity type is out of the connector scope.

    The platform only sends entities in scope, except in playbooks. So the internal
    enrichment connector skips the entity in a playbook, and treats this error as a
    failure outside a playbook (the work ends in error).
    """
