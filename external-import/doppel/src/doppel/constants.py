import requests

RETRYABLE_REQUEST_ERRORS = (
    requests.Timeout,
    requests.ConnectionError,
)

STIX_VERSION = "2.1"
