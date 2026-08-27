"""Converter tests against shapes taken from the captured tenant payload.

Covers the edge cases the sample proved real:
- empty description
- duplicated entitySnapshot across issues (System emitted once, targeted twice)
- actors: null inside threatDetectionDetails
- tags with slashes in keys

Instantiate the processor however the SDK test conventions prefer; only
_convert and the models are exercised here, no I/O.
"""

import pytest
from wiz_cloud.models import WizIssue

SIGNIN_ISSUE = {
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

EMPTY_DESCRIPTION_ISSUE = {
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
        "providerId": "arn:aws:ec2:us-east-2:998231069301:instance/i-038b4a2cfb0c1f036",
        "region": "us-east-2",
        "tags": {"Name": "tivan-eleonore-vm", "Wiz/wz": "666", "owner": "tivan"},
    },
    "sourceRules": [{"name": "Service account token was accessed"}],
    "threatDetectionDetails": {"actors": None},
}

# Same snapshot id as EMPTY_DESCRIPTION_ISSUE: the sample shows the same VM
# backing three distinct issues.
DUPLICATE_SNAPSHOT_ISSUE = {
    **EMPTY_DESCRIPTION_ISSUE,
    "id": "8dd5ce0a-0f7d-5f0e-aa08-332fe563c654",
    "createdAt": "2026-06-30T10:53:41.155017Z",
}


class TestWizIssueModel:
    def test_parses_full_issue(self):
        issue = WizIssue.model_validate(SIGNIN_ISSUE)
        assert issue.rule_name == "Wiz Sign-in from Unusual Country"
        assert issue.entity_snapshot.external_id == "mlipebtwsndhxdmnzdwrxzmio"
        assert issue.threat_detection_details.actors[0].type == "SERVICE_ACCOUNT"

    def test_empty_description_and_null_actors(self):
        issue = WizIssue.model_validate(EMPTY_DESCRIPTION_ISSUE)
        assert issue.description == ""
        assert issue.threat_detection_details.actors is None
        assert issue.entity_snapshot.tags["Wiz/wz"] == "666"


class TestConversion:
    @pytest.fixture()
    def processor(self):
        """Build a WizIssuesProcessor without running post_init I/O.

        Adjust to the SDK test conventions (settings fixture / dependency
        injection). The assertions below only need _convert.
        """
        raise NotImplementedError

    def test_incident_name_is_rule_plus_resource(self, processor):
        issue = WizIssue.model_validate(SIGNIN_ISSUE)
        objects = processor._convert(issue, systems_cache={})
        incident = objects[0]
        assert incident.name == "Wiz Sign-in from Unusual Country - TA-733-INTEG-ING"

    def test_empty_description_falls_back_to_none(self, processor):
        issue = WizIssue.model_validate(EMPTY_DESCRIPTION_ISSUE)
        incident = processor._convert(issue, systems_cache={})[0]
        assert incident.description is None
        assert incident.name == "Service account token was accessed - tivan-eleonore-vm"

    def test_duplicate_snapshot_yields_one_system_two_relationships(self, processor):
        cache = {}
        first = processor._convert(
            WizIssue.model_validate(EMPTY_DESCRIPTION_ISSUE), cache
        )
        second = processor._convert(
            WizIssue.model_validate(DUPLICATE_SNAPSHOT_ISSUE), cache
        )
        # System appears in the first conversion only; both carry a relationship.
        assert len(first) == 3  # incident, system, relationship
        assert len(second) == 2  # incident, relationship
        assert len(cache) == 1
