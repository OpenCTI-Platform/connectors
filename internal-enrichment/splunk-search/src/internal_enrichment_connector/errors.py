from __future__ import annotations


class SPLEnrichmentError(Exception):
    """Base error for SPL enrichment failures."""

    retryable: bool = False

    def __init__(
        self,
        message: str,
        indicator_id: str | None = None,
        cause: Exception | None = None,
    ):
        self.indicator_id = indicator_id
        self.cause = cause
        full_message = message
        if indicator_id:
            full_message = f"[{indicator_id}] {full_message}"
        if cause:
            full_message = f"{full_message} (cause: {cause})"
        super().__init__(full_message)


class SPLSyntaxError(SPLEnrichmentError):
    """Invalid SPL query syntax. Permanent failure."""

    retryable = False


class SPLTimeoutError(SPLEnrichmentError):
    """SPL query timed out. Transient failure."""

    retryable = True


class SPLAuthError(SPLEnrichmentError):
    """Splunk authN/authZ failure. Permanent failure."""

    retryable = False


class SPLConnectionError(SPLEnrichmentError):
    """Cannot reach Splunk instance. Transient failure."""

    retryable = True


class SPLResultParseError(SPLEnrichmentError):
    """Splunk results could not be parsed. Permanent failure."""

    retryable = False
