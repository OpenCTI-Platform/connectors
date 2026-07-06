class UnknownBackendError(Exception):
    pass


class _NoUnauthorized(Exception):
    """Dummy exception that is never raised — used for backends without entitlement checks."""
    pass
