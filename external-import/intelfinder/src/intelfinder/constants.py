from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

INTELFINDER_URL = "https://dash.intelfinder.io/api.php"
EXTERNAL_REFERENCE_URL = "https://dash.intelfinder.io/alert.php?id={}"

INTELFINDER_ALERT_DATA = {
    "key": None,  # API Key for the request.
    # To retrieve up to 20 alerts that have yet to be provided through the API,
    # ordered from oldest to newest, provide the following parameters
    "action": "getAlerts",
}
INTELFINDER_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
}
INTELFINDER_ERROR_CODE_MAP = {
    0: "Successful request",
    1: "API key is either invalid or not provided",
    2: "API is not enabled for the specific user",
    3: "Parameter 'action' is either invalid or not provided",
    4: "Request frequency exceeded limit",
    5: "The request performed is supposed to apply to a specific alert, but an invalid alert ID was provided",
    6: "Invalid value provided in any other parameter (additional details are provided in the documentation of relevant actions below)",
    7: "Another error has occurred, provided in the error field.",
}
INTELFINDER_DEFAULT_PAGE_SIZE = 20
# Rate limiting is applied to getAlerts queries after a response returns up to 20 alerts (i.e. all new alerts fit in the response).
# When there are over 20 alerts in the queue, no rate limiting is applied and you can send the next getAlerts request immediately afterwards.
RATE_LIMIT = 60
# 1: Very low
# 2: Low
# 3: Medium
# 4: High
# 5: Urgent
INTELFINDER_SEVERITY_MAP = {
    1: "low",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}

TLP_MAPPINGS = {
    "TLP:WHITE": TLP_WHITE,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:RED": TLP_RED,
}

# Default is 134217728 (128 MB) for RabbitMQ
RABBITMQ_MAX_DEFAULT = 134217728
TRUNCATE_MESSAGE = "TRUNCATED DUE TO SIZE LIMIT, CHECK INTELFINDER FOR FULL CONTENT."
