"""Custom exceptions raised by the OpenCTI models."""


class ProvenanceSummaryError(ValueError):
    """Raised when the OpenCTI provenance extension of a STIX object is malformed.

    The extension is present but cannot be read as a provenance summary: it is not
    a mapping, or its content does not follow the extension contract. When the
    content fails validation, the pydantic `ValidationError` is chained as the
    `__cause__` of this exception.
    """
