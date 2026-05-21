import requests

RETRYABLE_REQUEST_ERRORS = (
    requests.Timeout,
    requests.ConnectionError,
)
