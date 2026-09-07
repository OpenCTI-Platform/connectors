import requests

# OpenCTI connector releases track the pinned pycti version. Bump this value
# whenever the connector is released against a new OpenCTI version.
DOPPEL_CLIENT_VERSION = "7.260901.0"
DOPPEL_ATTRIBUTION_HEADERS = {
    "x-doppel-client": f"opencti/{DOPPEL_CLIENT_VERSION}",
    "User-Agent": f"doppel-opencti/{DOPPEL_CLIENT_VERSION}",
}

RETRYABLE_REQUEST_ERRORS = (
    requests.Timeout,
    requests.ConnectionError,
)

DOPPEL_ALERT_TYPES_EXCEPT_DOMAIN_AND_TELCO = [
    # 'domains',
    # 'telco',
    "social_media",
    "mobile_apps",
    "ecommerce",
    "crypto",
    "email",
    "paid_ads",
    "darkweb",
]
