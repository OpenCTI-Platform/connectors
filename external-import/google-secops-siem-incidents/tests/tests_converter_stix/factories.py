"""Polyfactory factories for converter-stix tests.

Reuses chronicle-client factories where possible, adds converter-specific
helpers for building Outcome lists that represent observables.
"""

from connectors_sdk.models import OrganizationAuthor, TLPMarking
from connectors_sdk.models.enums import TLPLevel
from polyfactory.factories.pydantic_factory import ModelFactory

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


# ---------------------------------------------------------------------------
# Model factories — deterministic defaults, override per-test
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
    time_window = TimeWindow(
        start_time="2025-01-01T00:00:00Z", end_time="2025-01-01T12:00:00Z"
    )


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
# Outcome builder helpers — construct typed outcome lists for each mapper
# ---------------------------------------------------------------------------


def make_hostname_outcomes(hostname: str) -> list[Outcome]:
    """Build outcomes list with a principal hostname."""
    return [
        OutcomeFactory.build(name="principal_hostname", string_val=hostname),
    ]


def make_ip_outcomes(
    ips: list[str],
    *,
    is_ipv6: bool | None = None,
) -> list[Outcome]:
    """Build outcomes list with principal IPs and optional IPv6 flag."""
    outcomes = [
        OutcomeFactory.build(
            name="principal_ip",
            string_seq=StringSeqFactory.build(string_vals=ips),
        ),
    ]
    if is_ipv6 is not None:
        outcomes.append(
            OutcomeFactory.build(
                name="SourceIsIpv6",
                string_val=str(is_ipv6).lower(),
            ),
        )
    return outcomes


def make_user_outcomes(
    principal_users: list[str] | None = None,
    target_users: list[str] | None = None,
) -> list[Outcome]:
    """Build outcomes with principal and target user IDs."""
    outcomes: list[Outcome] = []
    if principal_users:
        outcomes.append(
            OutcomeFactory.build(
                name="principal_user_userid",
                string_seq=StringSeqFactory.build(string_vals=principal_users),
            ),
        )
    if target_users:
        outcomes.append(
            OutcomeFactory.build(
                name="target_user_userid",
                string_seq=StringSeqFactory.build(string_vals=target_users),
            ),
        )
    return outcomes


def make_file_outcomes(
    *,
    principal_path: str | None = None,
    principal_sha256: str | None = None,
    target_path: str | None = None,
    target_sha256: str | None = None,
) -> list[Outcome]:
    """Build outcomes for file observables."""
    outcomes: list[Outcome] = []
    if principal_path is not None:
        outcomes.append(
            OutcomeFactory.build(
                name="principal_process_file_full_path",
                string_val=principal_path,
            ),
        )
    if principal_sha256 is not None:
        outcomes.append(
            OutcomeFactory.build(
                name="principal_process_file_sha256",
                string_val=principal_sha256,
            ),
        )
    if target_path is not None:
        outcomes.append(
            OutcomeFactory.build(
                name="target_process_file_full_path",
                string_val=target_path,
            ),
        )
    if target_sha256 is not None:
        outcomes.append(
            OutcomeFactory.build(
                name="target_process_file_sha256",
                string_val=target_sha256,
            ),
        )
    return outcomes


def make_risk_score_outcome(score: str) -> Outcome:
    """Build a single risk_score outcome."""
    return OutcomeFactory.build(name="risk_score", int64_val=score)


# ---------------------------------------------------------------------------
# STIX common helpers
# ---------------------------------------------------------------------------


def make_author():
    """Return the standard author STIX identity for Google SecOps."""
    return OrganizationAuthor(name="Google SecOps").to_stix2_object()


def make_tlp_marking(level: str = "amber"):
    """Return a TLP marking STIX object."""
    return TLPMarking(level=TLPLevel(level)).to_stix2_object()


def make_full_alert(
    *,
    fields: list[AlertField] | None = None,
    outcomes: list[Outcome] | None = None,
    rule_type: str = "MULTI_EVENT",
    severity: str = "HIGH",
    tags: str = "phishing,malware",
    detection_timestamp: str = "2025-01-01T06:00:00Z",
) -> tuple[Alert, RuleMetadata]:
    """Build a complete Alert + RuleMetadata pair for converter tests."""
    alert = AlertFactory.build(
        fields=fields
        or [
            AlertFieldFactory.build(name="ip", string_val="185.100.87.136"),
            AlertFieldFactory.build(name="hostname", string_val="srv01"),
        ],
        outcomes=outcomes or [make_risk_score_outcome("75")],
        rule_type=rule_type,
        detection_timestamp=detection_timestamp,
    )
    rule_metadata = RuleMetadataFactory.build(
        properties=RulePropertiesFactory.build(
            metadata={
                "severity": severity,
                "tags": tags,
            },
        ),
    )
    return alert, rule_metadata
