import requests

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
