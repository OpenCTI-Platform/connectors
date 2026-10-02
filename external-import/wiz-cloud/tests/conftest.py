"""Pytest configuration and shared fixtures for Wiz Cloud tests."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Add src/ to path so we can import the connector package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from connectors_sdk.models import OrganizationAuthor, System, TLPMarking  # noqa: E402
from wiz_client.models import WizIssue, WizVulnerabilityFinding  # noqa: E402
from wiz_cloud.processors import WizIssuesProcessor  # noqa: E402
from wiz_cloud.processors.issues_processor.converters import (  # noqa: E402
    IssueConverter,
    VulnerabilityConverter,
)
from wiz_cloud.settings import WizCloudConfig  # noqa: E402
from wiz_cloud.state import WizConnectorState  # noqa: E402


@pytest.fixture
def signin_issue_data() -> dict:
    """A complete issue with a populated threatDetectionDetails.actors list."""
    return {
        "id": "22b081f9-42d1-5b53-a504-1ddfbf28d53e",
        "type": "THREAT_DETECTION",
        "severity": "HIGH",
        "status": "OPEN",
        "createdAt": "2026-08-24T15:07:37.534962Z",
        "updatedAt": "2026-08-24T15:07:37.534962Z",
        "firstEventAt": "2026-08-24T14:59:43.407421Z",
        "lastEventAt": "2026-08-24T14:59:43.407421Z",
        "description": "Detects Wiz login from an unusual country.",
        "openReason": "ISSUE_DISCOVERED",
        "url": "https://app.wiz.io/issues#~(issue~'22b081f9')",
        "entitySnapshot": {
            "id": "b9e464fc-4b1a-5745-8d30-366690b946b8",
            "name": "TA-733-INTEG-ING",
            "type": "SERVICE_ACCOUNT",
            "externalId": "mlipebtwsndhxdmnzdwrxzmio",
            "cloudPlatform": "Wiz",
            "cloudProviderURL": "",
            "providerId": "",
            "region": "",
            "tags": {},
        },
        "sourceRules": [{"name": "Wiz Sign-in from Unusual Country"}],
        "threatDetectionDetails": {
            "actors": [
                {
                    "id": "b9e464fc",
                    "name": "TA-733-INTEG-ING",
                    "externalId": "mlipebtwsndhxdmnzdwrxzmio",
                    "providerUniqueId": None,
                    "type": "SERVICE_ACCOUNT",
                }
            ]
        },
    }


@pytest.fixture
def empty_description_issue_data() -> dict:
    """An issue with an empty description, null actors and slashed tag keys."""
    return {
        "id": "15811dfb-9cdf-539a-951f-d7961526d74d",
        "type": "THREAT_DETECTION",
        "severity": "MEDIUM",
        "status": "OPEN",
        "createdAt": "2026-07-30T11:25:18.878245Z",
        "updatedAt": "2026-08-10T10:08:35.813267Z",
        "firstEventAt": "2026-07-30T11:25:03.631Z",
        "lastEventAt": "2026-08-10T10:08:03.4Z",
        "description": "",
        "openReason": "ISSUE_DISCOVERED",
        "url": "https://app.wiz.io/issues#~(issue~'15811dfb')",
        "entitySnapshot": {
            "id": "8728411e-1a43-55a2-801e-44ffcb5a3dfa",
            "name": "tivan-eleonore-vm",
            "type": "VIRTUAL_MACHINE",
            "externalId": "i-038b4a2cfb0c1f036",
            "cloudPlatform": "AWS",
            "cloudProviderURL": "",
            "providerId": (
                "arn:aws:ec2:us-east-2:998231069301:instance/i-038b4a2cfb0c1f036"
            ),
            "region": "us-east-2",
            "tags": {"Name": "tivan-eleonore-vm", "Wiz/wz": "666", "owner": "tivan"},
        },
        "sourceRules": [{"name": "Service account token was accessed"}],
        "threatDetectionDetails": {"actors": None},
    }


@pytest.fixture
def duplicate_snapshot_issue_data(empty_description_issue_data) -> dict:
    """A distinct issue backed by the same entitySnapshot.

    The captured tenant payload shows the same VM behind three issues, which
    is what the System deduplication cache has to handle.
    """
    return {
        **empty_description_issue_data,
        "id": "8dd5ce0a-0f7d-5f0e-aa08-332fe563c654",
        "createdAt": "2026-06-30T10:53:41.155017Z",
    }


@pytest.fixture
def signin_issue(signin_issue_data) -> WizIssue:
    """Parsed WizIssue model from the full sign-in issue data."""
    return WizIssue.model_validate(signin_issue_data)


@pytest.fixture
def empty_description_issue(empty_description_issue_data) -> WizIssue:
    """Parsed WizIssue model from the empty-description issue data."""
    return WizIssue.model_validate(empty_description_issue_data)


@pytest.fixture
def duplicate_snapshot_issue(duplicate_snapshot_issue_data) -> WizIssue:
    """Parsed WizIssue model sharing its entitySnapshot with another issue."""
    return WizIssue.model_validate(duplicate_snapshot_issue_data)


@pytest.fixture
def vulnerability_finding_data() -> dict:
    """A kernel CVE finding with CVSS v3 metrics and no CVSS v4 block."""
    return {
        "id": "4f6f2001-3a9b-5ef7-a934-e6780bdfeb0b",
        "name": "CVE-2026-46333",
        "description": "The package `kernel` was detected on a machine.",
        "CVEDescription": (
            "In the Linux kernel, the following vulnerability has been resolved."
        ),
        "CVSSSeverity": "HIGH",
        "score": 7.1,
        "severity": "HIGH",
        "status": "OPEN",
        "hasCisaKevExploit": False,
        "portalUrl": (
            "https://app.wiz.io/explorer/vulnerability-findings#~(entity~(~'4f6f2001))"
        ),
        "firstDetectedAt": "2026-05-26T14:03:31.119827Z",
        "lastDetectedAt": "2026-08-28T06:08:26Z",
        "epssSeverity": "HIGH",
        "epssPercentile": 72.4,
        "epssProbability": 1.5,
        "cvssv2": {
            "attackVector": None,
            "attackComplexity": None,
            "confidentialityImpact": None,
            "integrityImpact": None,
            "availabilityImpact": None,
        },
        "cvssv3": {
            "attackVector": "LOCAL",
            "attackComplexity": "LOW",
            "privilegesRequired": "LOW",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "NONE",
            "exploitCodeMaturity": None,
            "userInteractionRequired": False,
            "scope": "UNCHANGED",
        },
        "cvssv4": None,
        "vulnerableAsset": {
            "id": "8728411e-1a43-55a2-801e-44ffcb5a3dfa",
            "type": "VIRTUAL_MACHINE",
            "name": "tivan-eleonore-vm",
            "region": "us-east-2",
            "providerUniqueId": (
                "arn:aws:ec2:us-east-2:998231069301:instance/i-038b4a2cfb0c1f036"
            ),
            "cloudProviderURL": (
                "https://us-east-2.console.aws.amazon.com/ec2/v2/home"
            ),
            "cloudPlatform": "AWS",
            "status": "Active",
            "tags": {"Name": "tivan-eleonore-vm", "owner": "tivan"},
        },
    }


@pytest.fixture
def second_asset_finding_data(vulnerability_finding_data) -> dict:
    """A finding on a different asset, used to test per-asset attribution."""
    return {
        **vulnerability_finding_data,
        "id": "faa59c04-b85f-598a-ba11-26069ca558c1",
        "name": "CVE-2026-3039",
        "CVEDescription": (
            "BIND servers are vulnerable to excessive memory consumption."
        ),
        "vulnerableAsset": {
            **vulnerability_finding_data["vulnerableAsset"],
            "id": "b9e464fc-4b1a-5745-8d30-366690b946b8",
            "name": "TA-733-INTEG-ING",
        },
    }


@pytest.fixture
def empty_cve_description_finding_data(vulnerability_finding_data) -> dict:
    """A finding whose CVEDescription is empty, forcing the fallback."""
    return {**vulnerability_finding_data, "CVEDescription": ""}


@pytest.fixture
def vulnerability_finding(vulnerability_finding_data) -> WizVulnerabilityFinding:
    """The kernel CVE finding, parsed as a WizVulnerabilityFinding."""
    return WizVulnerabilityFinding.model_validate(vulnerability_finding_data)


@pytest.fixture
def author() -> OrganizationAuthor:
    """The Wiz author, added to every object."""
    return OrganizationAuthor(name="Wiz")


@pytest.fixture
def marking() -> TLPMarking:
    """The TLP marking, added to every object."""
    return TLPMarking(level="amber+strict")


@pytest.fixture
def issue_converter(author, marking) -> IssueConverter:
    """An IssueConverter with the default author and marking."""
    return IssueConverter(author=author, marking=marking)


@pytest.fixture
def vulnerability_converter(author, marking) -> VulnerabilityConverter:
    """A VulnerabilityConverter with the default author and marking."""
    return VulnerabilityConverter(author=author, marking=marking)


def _make_config(**overrides) -> WizCloudConfig:
    """Build a WizCloudConfig with all required fields set.

    Args:
        **overrides: Fields to change from the default values.

    Returns:
        A validated WizCloudConfig.
    """
    return WizCloudConfig(
        api_url="https://api.us17.app.wiz.io/graphql",
        client_id="id",
        client_secret="secret",
        **overrides,
    )


@pytest.fixture
def make_config():
    """Function to build a WizCloudConfig, for tests that need other settings."""
    return _make_config


@pytest.fixture
def processor(author, marking) -> WizIssuesProcessor:
    """A WizIssuesProcessor for collect() and transform() tests, with no network calls.

    post_init() is not called, because it creates the HTTP client and reads
    the settings. This fixture sets the same attributes instead. The Wiz
    client, the logger and the state are fakes.

    Vulnerability import is off, like the default setting. To turn it on, set
    processor._config = make_config(import_vulnerabilities=True).
    """
    processor = WizIssuesProcessor()
    processor._config = _make_config()
    processor._client = MagicMock()
    processor._author = author
    processor._marking = marking
    processor._issue_converter = IssueConverter(author=author, marking=marking)
    processor._vulnerability_converter = VulnerabilityConverter(
        author=author, marking=marking
    )
    processor.logger = MagicMock()
    processor.state = WizConnectorState()
    return processor


@pytest.fixture
def system(author, marking) -> System:
    """The System that an issue creates for its cloud asset."""
    return System(name="tivan-eleonore-vm", author=author, markings=[marking])
