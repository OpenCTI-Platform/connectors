class ShodanInternetDbInvalidIPv4AddressError(Exception):
    pass


class ShodanInternetDbEntityNotInScopeError(Exception):
    pass


class ShodanInternetDbApiError(Exception):
    pass


class ShodanInternetDbNotFoundError(Exception):
    pass


class ShodanInternetDbExtractAndCheckMarkingsError(Exception):
    pass


class ShodanInternetDbInvalidTlpLevelError(Exception):
    pass


class ShodanInternetDbRateLimitError(Exception):
    """Raised on HTTP 429. Deliberately not handled by process_message so the
    enrichment work is reported as failed instead of silently processed."""
