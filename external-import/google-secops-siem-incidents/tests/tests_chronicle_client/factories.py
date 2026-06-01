"""Shared polyfactory ModelFactory classes and config helpers for chronicle client tests."""

from unittest.mock import MagicMock, patch

from google_secops_siem_incidents.client_api import GoogleSecOpsApiClient
from google_secops_siem_incidents.models.rule_alert_response import (
    Alert,
    AlertField,
    Outcome,
    RuleAlert,
    RuleAlertResponse,
    RuleMetadata,
    RuleProperties,
    StringSeq,
    TimeWindow,
)
from google_secops_siem_incidents.settings import GoogleSecOpsConfig
from polyfactory.factories.pydantic_factory import ModelFactory


# ---------------------------------------------------------------------------
# Response model factories — lock noisy defaults, override per test
# ---------------------------------------------------------------------------
class TimeWindowFactory(ModelFactory):
    __model__ = TimeWindow

    start_time = "2025-01-01T00:00:00Z"
    end_time = "2025-01-01T12:00:00Z"


class AlertFieldFactory(ModelFactory):
    __model__ = AlertField

    field_path = None
    string_val = None


class StringSeqFactory(ModelFactory):
    __model__ = StringSeq

    string_vals = []


class OutcomeFactory(ModelFactory):
    __model__ = Outcome

    int64_val = None
    string_val = None
    string_seq = None
    field_path = None


class AlertFactory(ModelFactory):
    __model__ = Alert

    result_events = {}
    result_entity_events = {}
    outcomes = []
    fields = []
    rule_type = "SINGLE_EVENT"
    alerting_type = "ALERTING"
    detection_timestamp = "2025-01-01T06:00:00Z"
    commit_timestamp = "2025-01-01T06:00:01Z"


class RulePropertiesFactory(ModelFactory):
    __model__ = RuleProperties

    metadata = {}


class RuleMetadataFactory(ModelFactory):
    __model__ = RuleMetadata


class RuleAlertFactory(ModelFactory):
    __model__ = RuleAlert

    alerts = []


class RuleAlertResponseFactory(ModelFactory):
    __model__ = RuleAlertResponse

    rule_alerts = []
    too_many_alerts = False


# ---------------------------------------------------------------------------
# Config + client helpers (GoogleSecOpsConfig is BaseSettings — no factory)
# ---------------------------------------------------------------------------
def make_config(**overrides) -> GoogleSecOpsConfig:
    """Build a minimal valid GoogleSecOpsConfig, override specific fields per test."""
    defaults: dict = {
        "project_id": "test-project",
        "project_region": "us",
        "project_instance": "test-instance-uuid",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
        "private_key_id": "key-id-1",
        "client_email": "sa@test.iam.gserviceaccount.com",
        "client_id": "123456789",
        "client_cert_url": (
            "https://www.googleapis.com/robot/v1/metadata/x509/sa%40test.iam.gserviceaccount.com"
        ),
        "tlp_level": "amber",
    }
    defaults.update(overrides)
    return GoogleSecOpsConfig(**defaults)


def make_client(config: GoogleSecOpsConfig | None = None, valid_creds: bool = True):
    """Build a GoogleSecOpsApiClient with mocked credentials and return (client, mock_creds)."""
    if config is None:
        config = make_config()
    mock_creds = MagicMock()
    mock_creds.valid = valid_creds
    mock_creds.token = "test-bearer-token"
    with patch(
        "google_secops_siem_incidents.client_api.Credentials.from_service_account_info",
        return_value=mock_creds,
    ):
        client = GoogleSecOpsApiClient(config=config)
    return client, mock_creds
