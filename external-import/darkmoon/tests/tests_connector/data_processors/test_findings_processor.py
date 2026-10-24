"""Tests for `FindingsProcessor`.

They check both the generic `BaseDataProcessor` contract and the Darkmoon
finding -> STIX mapping (Vulnerability, Note, Attack Pattern, Report).
"""

from unittest.mock import MagicMock

from connector.data_processors.findings_processor import FindingsProcessor
from connector.state import ConnectorState
from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    AttackPattern,
    Note,
    OrganizationAuthor,
    Relationship,
    Report,
    TLPMarking,
    Vulnerability,
)


def _build_processor(settings, state, fake_logger) -> FindingsProcessor:
    processor = FindingsProcessor()
    processor.settings = settings
    processor.state = state
    processor.work_manager = MagicMock()
    processor.logger = fake_logger
    processor.post_init()
    return processor


def test_findings_processor_implements_base_data_processor_contract():
    """`FindingsProcessor` must implement the `BaseDataProcessor` contract."""
    assert issubclass(FindingsProcessor, BaseDataProcessor)
    FindingsProcessor()  # must not raise: collect/transform are implemented


def test_full_pipeline_runs(settings_for_export, fake_logger):
    """The full collect -> transform -> send pipeline must run without error."""
    processor = _build_processor(settings_for_export, ConnectorState(), fake_logger)
    processor.process()  # work_manager is mocked; send() is inherited


def test_collect_reads_campaign_bundles(settings_for_export, fake_logger):
    """`collect` must read the on-disk export into campaign bundles."""
    processor = _build_processor(settings_for_export, ConnectorState(), fake_logger)

    bundles = processor.collect()

    assert len(bundles) == 1
    bundle = bundles[0]
    assert bundle.campaign.id == "camp_20260301_abcd1234"
    assert len(bundle.findings) == 2
    assert bundle.target is not None
    assert bundle.target.host == "app.example.com"


def test_transform_produces_expected_stix_objects(settings_for_export, fake_logger):
    """`transform` must map findings to the expected STIX objects."""
    state = ConnectorState()
    processor = _build_processor(settings_for_export, state, fake_logger)

    objects = processor.transform(processor.collect())
    assert objects is not None

    authors = [o for o in objects if isinstance(o, OrganizationAuthor)]
    markings = [o for o in objects if isinstance(o, TLPMarking)]
    vulns = [o for o in objects if isinstance(o, Vulnerability)]
    notes = [o for o in objects if isinstance(o, Note)]
    attack_patterns = [o for o in objects if isinstance(o, AttackPattern)]
    relationships = [o for o in objects if isinstance(o, Relationship)]
    reports = [o for o in objects if isinstance(o, Report)]

    # One author, one marking, two findings -> two vulns + two notes,
    # one ATT&CK technique (T1190) -> one attack pattern + one relationship,
    # one campaign -> one report.
    assert len(authors) == 1
    assert len(markings) == 1
    assert len(vulns) == 2
    assert len(notes) == 2
    assert len(attack_patterns) == 1
    assert len(relationships) == 1
    assert len(reports) == 1

    # CVE finding is named after its CVE and keeps the title as an alias.
    cve_vuln = next(v for v in vulns if v.name == "CVE-2021-23017")
    assert cve_vuln.aliases == ["Outdated nginx (CVE-2021-23017)"]
    # CWE-787 embedded in the category is detected.
    assert cve_vuln.cwe_ids == ["CWE-787"]
    assert cve_vuln.cvss_v3_base_score == 8.1

    # Non-CVE finding is named after its title and carries CVSS severity.
    sqli_vuln = next(v for v in vulns if v.name == "SQL Injection in login form")
    assert sqli_vuln.cvss_v3_base_score == 9.8
    assert str(sqli_vuln.cvss_v3_base_severity) == "CRITICAL"
    assert sqli_vuln.score == 98

    # The note references its vulnerability and carries the evidence.
    sqli_note = next(n for n in notes if "SQL Injection" in (n.abstract or ""))
    assert sqli_note.objects and sqli_note.objects[0].id == sqli_vuln.id
    assert "sqlmap" in sqli_note.content
    assert "Raw request" in sqli_note.content

    # The attack pattern maps the MITRE technique and links to the SQLi vuln.
    attack_pattern = attack_patterns[0]
    assert attack_pattern.mitre_id == "T1190"
    rel = relationships[0]
    assert rel.source.id == sqli_vuln.id
    assert rel.target.id == attack_pattern.id

    # The report groups every produced object.
    report = reports[0]
    assert "camp_20260301_abcd1234" in report.name
    assert report.objects is not None
    object_ids = {o.id for o in report.objects}
    assert sqli_vuln.id in object_ids
    assert cve_vuln.id in object_ids

    # State checkpoint is advanced to the campaign date.
    assert state.last_campaign_date is not None


def test_transform_output_is_valid_stix(settings_for_export, fake_logger):
    """Every produced object must serialize to a STIX 2.1 object."""
    processor = _build_processor(settings_for_export, ConnectorState(), fake_logger)

    objects = processor.transform(processor.collect())

    for obj in objects:
        stix_object = obj.to_stix2_object()
        assert stix_object.id


def test_since_filter_excludes_old_campaigns(settings_for_export, fake_logger):
    """Campaigns older than the checkpoint must be excluded."""
    from datetime import datetime, timezone

    state = ConnectorState(last_campaign_date=datetime(2026, 6, 1, tzinfo=timezone.utc))
    processor = _build_processor(settings_for_export, state, fake_logger)

    assert processor.collect() == []


def test_collect_ignores_generic_last_run(settings_for_export, fake_logger):
    """`collect` must checkpoint on `last_campaign_date`/`import_since` only.

    The SDK advances the generic `last_run` after every successful callback
    (including empty runs when findings import is disabled). Using it as the
    checkpoint would skip campaigns dated between `import_since` and that run, so
    `collect` must ignore `last_run` entirely.
    """
    from datetime import datetime, timezone

    # last_run is after the fixture campaign (2026-03-01) but there is no
    # campaign checkpoint yet; import_since (2026-01-01) must win and the
    # campaign must still be collected.
    state = ConnectorState(last_run=datetime(2026, 9, 1, tzinfo=timezone.utc))
    processor = _build_processor(settings_for_export, state, fake_logger)

    assert len(processor.collect()) == 1


def test_cvss_zero_score_is_preserved(settings_for_export, fake_logger):
    """A CVSS score of 0.0 is valid and must not fall back to severity scoring."""
    from darkmoon_client.models import DarkmoonFinding

    processor = _build_processor(settings_for_export, ConnectorState(), fake_logger)
    finding = DarkmoonFinding(
        title="Informational", severity="critical", cvss_score=0.0
    )

    vuln = processor._build_vulnerability(finding)

    # Without the fix, score would become the severity-derived 90.
    assert vuln.cvss_v3_base_score == 0.0
    assert vuln.score == 0


def test_note_id_is_not_derived_from_timestamp(settings_for_export, fake_logger):
    """Evidence notes must not set `created` (it feeds the deterministic id)."""
    from darkmoon_client.models import DarkmoonFinding

    processor = _build_processor(settings_for_export, ConnectorState(), fake_logger)
    finding = DarkmoonFinding(
        title="SQLi", severity="high", discovered_at="2026-03-01T10:12:00Z"
    )
    vuln = processor._build_vulnerability(finding)

    note = processor._build_note(finding, vuln)

    assert note.created is None
    assert note.publication_date is None
    # The discovery timestamp is kept in the human-readable content.
    assert "2026-03-01T10:12:00Z" in note.content
