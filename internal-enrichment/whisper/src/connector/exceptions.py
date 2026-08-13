class WhisperClientError(Exception):
    """Base exception for the Whisper API client."""


class WhisperAuthError(WhisperClientError):
    """Whisper API rejected the API key (HTTP 401/403)."""


class WhisperTransportError(WhisperClientError):
    """Request failed after retries (timeout, 5xx, connection error)."""


class WhisperQueryError(WhisperClientError):
    """Whisper API returned a query-level error (HTTP 4xx other than auth)."""


class StixMappingError(Exception):
    """Raised when a Whisper node/edge can't be mapped to a STIX object."""


class WhisperTlpError(Exception):
    """Raised when an observable's TLP marking exceeds ``whisper.max_tlp``.

    The connector must refuse to enrich beyond the configured TLP ceiling
    — the connector's API key effectively grants access to whatever the
    OpenCTI user it impersonates can see, so enriching past the ceiling
    would leak intel to a less-trusted Whisper account.
    """
