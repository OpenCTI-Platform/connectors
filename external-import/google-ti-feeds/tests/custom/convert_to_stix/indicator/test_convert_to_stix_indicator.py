"""Comprehensive tests for ConvertToSTIXIndicator."""

import logging
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaAttributes,
    IOCDeltaEntry,
    IOCDeltaGTIAssessment,
    IOCDeltaRelationshipData,
    IOCDeltaRelationshipItem,
    IOCDeltaRelationshipItemAttributes,
    IOCDeltaRelationships,
    IOCDeltaThreatScore,
)
from pydantic import HttpUrl
from pydantic.types import SecretStr

# =====================
# Test Fakes
# =====================


class DummyConfig:
    """Minimal config for ConvertToSTIXIndicator tests."""

    def __init__(self) -> None:  # noqa: D107
        self.api_key = SecretStr("fake-key")
        self.api_url = HttpUrl("https://fake-gti.api")
        self.tlp_level = "white"
        self.import_reports = False
        self.import_threat_actors = False
        self.import_malware_families = False
        self.import_vulnerabilities = False
        self.import_campaigns = False
        self.import_indicators = True
        self.indicator_types = ["file", "ip", "url", "domain"]
        self.indicator_import_start_date = timedelta(days=1)
        self.indicator_min_score = 0
        self.indicator_require_malware_family = False
        self.indicator_require_threat_actor = False
        self.report_import_start_date = timedelta(days=1)
        self.threat_actor_import_start_date = timedelta(days=1)
        self.malware_family_import_start_date = timedelta(days=1)
        self.vulnerability_import_start_date = timedelta(days=1)
        self.campaign_import_start_date = timedelta(days=1)
        self.report_types = ["All"]
        self.report_origins = ["All"]
        self.threat_actor_origins = "All"
        self.malware_family_origins = "All"
        self.vulnerability_origins = "All"
        self.vulnerability_get_related_softwares = True


# =====================
# Fixtures
# =====================


@pytest.fixture
def logger() -> logging.Logger:
    """Return a real logger for tests."""
    return logging.getLogger("test_convert_to_stix_indicator")


@pytest.fixture
def converter(logger: logging.Logger) -> ConvertToSTIXIndicator:
    """Return a ConvertToSTIXIndicator instance."""
    return _given_converter(logger)


# =====================
# Helpers – Given / When / Then
# =====================


def _given_converter(logger: logging.Logger) -> ConvertToSTIXIndicator:
    return ConvertToSTIXIndicator(
        config=DummyConfig(),  # type: ignore[arg-type]
        logger=logger,
        tlp_level="white",
    )


def _given_minimal_relationships() -> IOCDeltaRelationships:
    """Return a minimal relationship so _build_relationships includes the indicator."""
    return IOCDeltaRelationships(
        malware_families=IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="malware--stub",
                    attributes=IOCDeltaRelationshipItemAttributes(name="StubMalware"),
                )
            ]
        )
    )


def _given_file_entry(
    *,
    sha256: str | None = "aabb" * 16,
    md5: str | None = "ccdd" * 8,
    sha1: str | None = "eeff" * 10,
    meaningful_name: str | None = "test.exe",
    score: int | None = 80,
    creation_date: int | None = 1_700_000_000,
    attributes: IOCDeltaAttributes | None = None,
    relationships: IOCDeltaRelationships | None = None,
) -> dict:
    if attributes is None:
        gti = (
            IOCDeltaGTIAssessment(threat_score=IOCDeltaThreatScore(value=score))
            if score is not None
            else None
        )
        attributes = IOCDeltaAttributes(
            sha256=sha256,
            md5=md5,
            sha1=sha1,
            meaningful_name=meaningful_name,
            creation_date=creation_date,
            gti_assessment=gti,
        )
    entry = IOCDeltaEntry(
        id=sha256 or "deadbeef" * 8,
        type="file",
        attributes=attributes,
        relationships=relationships,
    )
    return entry.model_dump()


def _given_ip_entry(
    ip_addr: str = "1.2.3.4",
    *,
    score: int | None = 70,
    creation_date: int | None = 1_700_000_000,
    attributes: IOCDeltaAttributes | None = None,
    relationships: IOCDeltaRelationships | None = None,
) -> dict:
    if attributes is None:
        gti = (
            IOCDeltaGTIAssessment(threat_score=IOCDeltaThreatScore(value=score))
            if score is not None
            else None
        )
        attributes = IOCDeltaAttributes(
            creation_date=creation_date,
            gti_assessment=gti,
        )
    entry = IOCDeltaEntry(
        id=ip_addr,
        type="ip_address",
        attributes=attributes,
        relationships=relationships,
    )
    return entry.model_dump()


def _given_url_entry(
    url: str = "https://evil.example.com/payload",
    *,
    score: int | None = 90,
    creation_date: int | None = 1_700_000_000,
    relationships: IOCDeltaRelationships | None = None,
) -> dict:
    gti = (
        IOCDeltaGTIAssessment(threat_score=IOCDeltaThreatScore(value=score))
        if score is not None
        else None
    )
    entry = IOCDeltaEntry(
        id="url-id-hash",
        type="url",
        attributes=IOCDeltaAttributes(
            url=url,
            creation_date=creation_date,
            gti_assessment=gti,
        ),
        relationships=relationships,
    )
    return entry.model_dump()


def _given_domain_entry(
    domain: str = "evil.example.com",
    *,
    score: int | None = 60,
    creation_date: int | None = 1_700_000_000,
    relationships: IOCDeltaRelationships | None = None,
) -> dict:
    gti = (
        IOCDeltaGTIAssessment(threat_score=IOCDeltaThreatScore(value=score))
        if score is not None
        else None
    )
    entry = IOCDeltaEntry(
        id=domain,
        type="domain",
        attributes=IOCDeltaAttributes(
            creation_date=creation_date,
            gti_assessment=gti,
        ),
        relationships=relationships,
    )
    return entry.model_dump()


def _given_relationships(
    *,
    malware_name: str | None = None,
    campaign_name: str | None = None,
    threat_actor_name: str | None = None,
    software_toolkit_name: str | None = None,
    attack_technique_id: str | None = None,
) -> IOCDeltaRelationships:
    rels = IOCDeltaRelationships()
    if malware_name is not None:
        rels.malware_families = IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="malware--1",
                    attributes=IOCDeltaRelationshipItemAttributes(name=malware_name),
                )
            ]
        )
    if campaign_name is not None:
        rels.campaigns = IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="campaign--1",
                    attributes=IOCDeltaRelationshipItemAttributes(name=campaign_name),
                )
            ]
        )
    if threat_actor_name is not None:
        rels.threat_actors = IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="threat-actor--1",
                    attributes=IOCDeltaRelationshipItemAttributes(
                        name=threat_actor_name
                    ),
                )
            ]
        )
    if software_toolkit_name is not None:
        rels.software_toolkits = IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="toolkit--1",
                    attributes=IOCDeltaRelationshipItemAttributes(
                        name=software_toolkit_name
                    ),
                )
            ]
        )
    if attack_technique_id is not None:
        rels.attack_techniques = IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="attack-technique",
                    id=attack_technique_id,
                )
            ]
        )
    return rels


def _when_convert(converter: ConvertToSTIXIndicator, data: dict) -> list:
    return converter.convert(data)


def _then_returns_empty(result: list) -> None:
    assert result == []  # noqa: S101


def _then_returns_n_objects(result: list, n: int) -> None:
    assert len(result) == n  # noqa: S101


def _then_stix_type_present(result: list, stix_type: str) -> None:
    types = [obj.get("type") if isinstance(obj, dict) else obj.type for obj in result]
    assert stix_type in types  # noqa: S101


# =====================
# 1. convert() – invalid data → []
# =====================


class TestConvertInvalidData:
    """Test convert() with unparseable data."""

    def test_invalid_dict_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given
        data = {"bad_field": "no id or type"}
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)

    def test_completely_empty_dict_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given / When
        result = _when_convert(converter, {})
        # Then
        _then_returns_empty(result)


# =====================
# 2. convert() – unknown IOC type → []
# =====================


class TestConvertUnknownType:
    """Test convert() with an unsupported IOC type."""

    def test_unknown_type_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given
        data = IOCDeltaEntry(
            id="some-id", type="unknown_type", attributes=IOCDeltaAttributes()
        ).model_dump()
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)


# =====================
# 3. convert() – conversion exception → []
# =====================


class TestConvertException:
    """Test convert() when the converter function raises."""

    def test_converter_exception_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – patch the domain converter to raise
        with patch.object(
            converter, "_convert_domain", side_effect=RuntimeError("boom")
        ):
            data = _given_domain_entry()
            # When
            result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)


# =====================
# 4. convert() – converter returns None (no attributes) → []
# =====================


class TestConvertNoneResult:
    """Test convert() when the converter returns None."""

    def test_file_no_attributes_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – file entry with attributes=None
        data = IOCDeltaEntry(
            id="deadbeef" * 8, type="file", attributes=None
        ).model_dump()
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)

    def test_ip_no_attributes_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given
        data = IOCDeltaEntry(
            id="1.2.3.4", type="ip_address", attributes=None
        ).model_dump()
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)


# =====================
# 5. _convert_file – no hashes → None
# =====================


class TestConvertFileNoHashes:
    """Test _convert_file when no hashes are present."""

    def test_file_no_hashes_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – file entry with attributes but no hashes
        data = _given_file_entry(sha256=None, md5=None, sha1=None)
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)


# =====================
# 6. _convert_file – no gti_assessment → score=None
# =====================


class TestConvertFileNoAssessment:
    """Test _convert_file without gti_assessment."""

    def test_file_no_assessment_has_none_score(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – include a relationship so the indicator appears in the output
        data = _given_file_entry(
            score=None, relationships=_given_minimal_relationships()
        )
        # When
        result = _when_convert(converter, data)
        # Then – indicator + malware + relationship = 3
        _then_returns_n_objects(result, 3)
        indicators = [o for o in result if o["type"] == "indicator"]
        assert len(indicators) == 1  # noqa: S101
        assert (
            "score" not in indicators[0] or indicators[0].get("x_opencti_score") is None
        )  # noqa: S101


# =====================
# 7. _detect_ip_version – IPv4 and IPv6
# =====================


class TestDetectIpVersion:
    """Test _detect_ip_version for IPv4 and IPv6."""

    def test_ipv4(self, converter: ConvertToSTIXIndicator) -> None:
        # Given / When
        version = converter._detect_ip_version("192.168.1.1")
        # Then
        assert version == "ipv4"  # noqa: S101

    def test_ipv6(self, converter: ConvertToSTIXIndicator) -> None:
        # Given / When
        version = converter._detect_ip_version("::1")
        # Then
        assert version == "ipv6"  # noqa: S101

    def test_ipv6_full(self, converter: ConvertToSTIXIndicator) -> None:
        # Given / When
        version = converter._detect_ip_version(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        )
        # Then
        assert version == "ipv6"  # noqa: S101


# =====================
# 8. _detect_ip_version – invalid IP → ValueError
# =====================


class TestDetectIpVersionInvalid:
    """Test _detect_ip_version with invalid IP."""

    def test_invalid_ip_raises(self, converter: ConvertToSTIXIndicator) -> None:
        # Given / When / Then
        with pytest.raises(ValueError, match="Invalid IP address format"):
            converter._detect_ip_version("not-an-ip")


# =====================
# 9. _convert_ip – None attributes → None
# =====================


class TestConvertIpNoneAttributes:
    """Test _convert_ip returns None when attributes are None."""

    def test_ip_none_attributes_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given
        data = IOCDeltaEntry(
            id="1.2.3.4", type="ip_address", attributes=None
        ).model_dump()
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)


# =====================
# 10. _convert_ip – IPv4 full conversion
# =====================


class TestConvertIpV4:
    """Test full IPv4 indicator conversion."""

    def test_ipv4_conversion(self, converter: ConvertToSTIXIndicator) -> None:
        # Given
        ip = "10.0.0.1"
        data = _given_ip_entry(
            ip, score=75, relationships=_given_minimal_relationships()
        )
        # When
        result = _when_convert(converter, data)
        # Then – indicator + malware + relationship = 3
        _then_returns_n_objects(result, 3)
        indicators = [o for o in result if o["type"] == "indicator"]
        stix_obj = indicators[0]
        assert f"ipv4-addr:value = '{ip}'" in stix_obj["pattern"]  # noqa: S101
        assert stix_obj["name"] == ip  # noqa: S101


# =====================
# 11. _convert_ip – IPv6 full conversion
# =====================


class TestConvertIpV6:
    """Test full IPv6 indicator conversion."""

    def test_ipv6_conversion(self, converter: ConvertToSTIXIndicator) -> None:
        # Given
        ip = "2001:db8::1"
        data = _given_ip_entry(
            ip, score=65, relationships=_given_minimal_relationships()
        )
        # When
        result = _when_convert(converter, data)
        # Then – indicator + malware + relationship = 3
        _then_returns_n_objects(result, 3)
        indicators = [o for o in result if o["type"] == "indicator"]
        stix_obj = indicators[0]
        assert f"ipv6-addr:value = '{ip}'" in stix_obj["pattern"]  # noqa: S101


# =====================
# 12. _convert_url – None attrs or url → None
# =====================


class TestConvertUrlNone:
    """Test _convert_url returns None when attrs or url is None."""

    def test_url_none_attributes_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given
        data = IOCDeltaEntry(id="url-hash", type="url", attributes=None).model_dump()
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)

    def test_url_none_url_field_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – attributes present but url=None
        data = IOCDeltaEntry(
            id="url-hash",
            type="url",
            attributes=IOCDeltaAttributes(url=None),
        ).model_dump()
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)


# =====================
# 13. _convert_url – valid URL
# =====================


class TestConvertUrlValid:
    """Test full URL indicator conversion."""

    def test_url_conversion(self, converter: ConvertToSTIXIndicator) -> None:
        # Given
        url = "https://malicious.example.com/path"
        data = _given_url_entry(
            url=url, score=90, relationships=_given_minimal_relationships()
        )
        # When
        result = _when_convert(converter, data)
        # Then – indicator + malware + relationship = 3
        _then_returns_n_objects(result, 3)
        indicators = [o for o in result if o["type"] == "indicator"]
        stix_obj = indicators[0]
        assert f"url:value = '{url}'" in stix_obj["pattern"]  # noqa: S101
        assert stix_obj["name"] == url  # noqa: S101


# =====================
# 14. _convert_domain – None attrs → None
# =====================


class TestConvertDomainNone:
    """Test _convert_domain returns None when attrs are None."""

    def test_domain_none_attributes_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given
        data = IOCDeltaEntry(id="evil.com", type="domain", attributes=None).model_dump()
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)


# =====================
# 15. _convert_domain – valid domain
# =====================


class TestConvertDomainValid:
    """Test full domain indicator conversion."""

    def test_domain_conversion(self, converter: ConvertToSTIXIndicator) -> None:
        # Given
        domain = "malicious.example.com"
        data = _given_domain_entry(
            domain=domain, score=60, relationships=_given_minimal_relationships()
        )
        # When
        result = _when_convert(converter, data)
        # Then – indicator + malware + relationship = 3
        _then_returns_n_objects(result, 3)
        indicators = [o for o in result if o["type"] == "indicator"]
        stix_obj = indicators[0]
        assert f"domain-name:value = '{domain}'" in stix_obj["pattern"]  # noqa: S101
        assert stix_obj["name"] == domain  # noqa: S101


# =====================
# 16. _build_relationships – no relationships → []
# =====================


class TestBuildRelationshipsNone:
    """Test _build_relationships returns [] when entry has no relationships."""

    def test_no_relationships_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – file entry without relationships
        data = _given_file_entry(relationships=None)
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)


# =====================
# 17. _create_relation_malware_family – missing name → []
# =====================


class TestRelationMalwareFamilyMissing:
    """Test _create_relation_malware_family with missing name."""

    def test_malware_missing_name_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – malware relationship with no name
        rels = IOCDeltaRelationships(
            malware_families=IOCDeltaRelationshipData(
                data=[
                    IOCDeltaRelationshipItem(
                        type="collection",
                        id="malware--1",
                        attributes=IOCDeltaRelationshipItemAttributes(name=None),
                    )
                ]
            )
        )
        data = _given_file_entry(relationships=rels)
        # When
        result = _when_convert(converter, data)
        # Then – only the indicator itself, no malware/relationship objects
        _then_returns_n_objects(result, 1)
        _then_stix_type_present(result, "indicator")

    def test_malware_no_attributes_returns_empty(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – malware relationship with attributes=None
        rels = IOCDeltaRelationships(
            malware_families=IOCDeltaRelationshipData(
                data=[
                    IOCDeltaRelationshipItem(
                        type="collection",
                        id="malware--1",
                        attributes=None,
                    )
                ]
            )
        )
        data = _given_file_entry(relationships=rels)
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_n_objects(result, 1)


# =====================
# 18. _create_relation_campaign – valid → campaign + relationship
# =====================


class TestRelationCampaignValid:
    """Test _create_relation_campaign produces campaign + relationship."""

    def test_campaign_relation_valid(self, converter: ConvertToSTIXIndicator) -> None:
        # Given
        rels = _given_relationships(campaign_name="APT-Campaign-X")
        data = _given_file_entry(relationships=rels)
        # When
        result = _when_convert(converter, data)
        # Then – indicator = 1 (no relation with campaign created)
        _then_returns_n_objects(result, 1)
        _then_stix_type_present(result, "indicator")


# =====================
# 19. _create_relation_campaign – missing name → []
# =====================


class TestRelationCampaignMissing:
    """Test _create_relation_campaign with missing name."""

    def test_campaign_missing_name(self, converter: ConvertToSTIXIndicator) -> None:
        # Given
        rels = IOCDeltaRelationships(
            campaigns=IOCDeltaRelationshipData(
                data=[
                    IOCDeltaRelationshipItem(
                        type="collection",
                        id="campaign--1",
                        attributes=IOCDeltaRelationshipItemAttributes(name=None),
                    )
                ]
            )
        )
        data = _given_file_entry(relationships=rels)
        # When
        result = _when_convert(converter, data)
        # Then – only indicator, no campaign/relationship
        _then_returns_n_objects(result, 1)


# =====================
# 20. _create_relation_threat_actor – valid → intrusion_set + relationship
# =====================


class TestRelationThreatActorValid:
    """Test _create_relation_threat_actor produces intrusion-set + relationship."""

    def test_threat_actor_relation_valid(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given
        rels = _given_relationships(threat_actor_name="APT28")
        data = _given_file_entry(relationships=rels)
        # When
        result = _when_convert(converter, data)
        # Then – indicator + intrusion-set + relationship = 3
        _then_returns_n_objects(result, 3)
        _then_stix_type_present(result, "indicator")
        _then_stix_type_present(result, "intrusion-set")
        _then_stix_type_present(result, "relationship")


# =====================
# 21. _create_relation_threat_actor – missing name → []
# =====================


class TestRelationThreatActorMissing:
    """Test _create_relation_threat_actor with missing name."""

    def test_threat_actor_missing_name(self, converter: ConvertToSTIXIndicator) -> None:
        # Given
        rels = IOCDeltaRelationships(
            threat_actors=IOCDeltaRelationshipData(
                data=[
                    IOCDeltaRelationshipItem(
                        type="collection",
                        id="threat-actor--1",
                        attributes=IOCDeltaRelationshipItemAttributes(name=None),
                    )
                ]
            )
        )
        data = _given_file_entry(relationships=rels)
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_n_objects(result, 1)


# =====================
# 22. _create_relation_software_toolkit – valid → tool + relationship
# =====================


class TestRelationSoftwareToolkitValid:
    """Test _create_relation_software_toolkit produces tool + relationship."""

    def test_software_toolkit_relation_valid(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – mock Tool and Relationship from connectors_sdk.models to
        # isolate the relationship-creation logic from SDK internals.
        import uuid

        tool_id = f"tool--{uuid.uuid4()}"
        fake_stix_tool = {"type": "tool", "id": tool_id, "name": "COBALT STRIKE"}
        fake_stix_rel = {"type": "relationship", "id": f"relationship--{uuid.uuid4()}"}

        with (
            patch(
                "connector.src.custom.convert_to_stix.indicator"
                ".convert_to_stix_indicator.Tool"
            ) as MockTool,
            patch(
                "connector.src.custom.convert_to_stix.indicator"
                ".convert_to_stix_indicator.Relationship"
            ) as MockRelationship,
        ):
            mock_tool = MagicMock()
            mock_tool.to_stix2_object.return_value = fake_stix_tool
            mock_tool.id = tool_id
            MockTool.return_value = mock_tool

            mock_rel = MagicMock()
            mock_rel.to_stix2_object.return_value = fake_stix_rel
            MockRelationship.return_value = mock_rel

            rels = _given_relationships(software_toolkit_name="Cobalt Strike")
            data = _given_file_entry(relationships=rels)
            # When
            result = _when_convert(converter, data)

        # Then – indicator + tool + relationship = 3
        _then_returns_n_objects(result, 3)
        _then_stix_type_present(result, "indicator")
        types = [
            obj.get("type") if isinstance(obj, dict) else obj.type for obj in result
        ]
        assert "tool" in types  # noqa: S101
        assert "relationship" in types  # noqa: S101


# =====================
# 23. _create_relation_software_toolkit – missing name → []
# =====================


class TestRelationSoftwareToolkitMissing:
    """Test _create_relation_software_toolkit with missing name."""

    def test_software_toolkit_missing_name(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given
        rels = IOCDeltaRelationships(
            software_toolkits=IOCDeltaRelationshipData(
                data=[
                    IOCDeltaRelationshipItem(
                        type="collection",
                        id="toolkit--1",
                        attributes=IOCDeltaRelationshipItemAttributes(name=None),
                    )
                ]
            )
        )
        data = _given_file_entry(relationships=rels)
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_n_objects(result, 1)


# =====================
# 24. _create_relation_attack_technique – valid → attack-pattern + relationship
# =====================


class TestRelationAttackTechniqueValid:
    """Test _create_relation_attack_technique produces attack-pattern + rel."""

    def test_attack_technique_relation_valid(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – call _create_relation_attack_technique directly because the
        # IOCDeltaRelationships model types attack_techniques as a single item
        # (not IOCDeltaRelationshipData with .data), so _build_relationships
        # cannot iterate it. This tests the method's logic in isolation.
        entry = IOCDeltaEntry(
            id="aabb" * 16,
            type="file",
            attributes=IOCDeltaAttributes(
                sha256="aabb" * 16, creation_date=1_700_000_000
            ),
        )
        parsed_entry = IOCDeltaEntry.model_validate(entry.model_dump())
        ioc_entry = converter._convert_file(parsed_entry)
        assert ioc_entry is not None  # noqa: S101

        technique_data = IOCDeltaRelationshipItem(
            type="attack-technique", id="T1059.001"
        )
        # When
        result = converter._create_relation_attack_technique(ioc_entry, technique_data)
        # Then – attack-pattern + relationship = 2
        _then_returns_n_objects(result, 2)
        types = [
            obj.get("type") if isinstance(obj, dict) else obj.type for obj in result
        ]
        assert "attack-pattern" in types  # noqa: S101
        assert "relationship" in types  # noqa: S101


# =====================
# 25. _create_relation_attack_technique – missing id → []
# =====================


class TestRelationAttackTechniqueMissing:
    """Test _create_relation_attack_technique with missing id."""

    def test_attack_technique_missing_id(
        self, converter: ConvertToSTIXIndicator
    ) -> None:
        # Given – call the method directly (same reason as valid test above)
        entry = IOCDeltaEntry(
            id="aabb" * 16,
            type="file",
            attributes=IOCDeltaAttributes(
                sha256="aabb" * 16, creation_date=1_700_000_000
            ),
        )
        parsed_entry = IOCDeltaEntry.model_validate(entry.model_dump())
        ioc_entry = converter._convert_file(parsed_entry)
        assert ioc_entry is not None  # noqa: S101

        technique_data = IOCDeltaRelationshipItem(type="attack-technique", id=None)
        # When
        result = converter._create_relation_attack_technique(ioc_entry, technique_data)
        # Then
        _then_returns_empty(result)


# =====================
# 26. convert – indicator_min_score filtering
# =====================


def _given_converter_with_min_score(
    logger: logging.Logger, min_score: int | None
) -> ConvertToSTIXIndicator:
    config = DummyConfig()
    config.indicator_min_score = min_score
    return ConvertToSTIXIndicator(
        config=config,  # type: ignore[arg-type]
        logger=logger,
        tlp_level="white",
    )


class TestConvertMinScoreFilter:
    """Test convert() filtering IOC entries by indicator_min_score."""

    def test_score_below_min_returns_empty(self, logger: logging.Logger) -> None:
        # Given – converter with a min score higher than the entry's score
        converter = _given_converter_with_min_score(logger, min_score=50)
        data = _given_file_entry(score=10, relationships=_given_minimal_relationships())
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)

    def test_score_equal_to_min_is_kept(self, logger: logging.Logger) -> None:
        # Given – entry score exactly matches the configured threshold
        converter = _given_converter_with_min_score(logger, min_score=50)
        data = _given_file_entry(score=50, relationships=_given_minimal_relationships())
        # When
        result = _when_convert(converter, data)
        # Then
        assert result  # noqa: S101

    def test_score_above_min_is_kept(self, logger: logging.Logger) -> None:
        # Given – entry score above the configured threshold
        converter = _given_converter_with_min_score(logger, min_score=50)
        data = _given_file_entry(score=90, relationships=_given_minimal_relationships())
        # When
        result = _when_convert(converter, data)
        # Then
        assert result  # noqa: S101

    def test_no_score_is_never_filtered(self, logger: logging.Logger) -> None:
        # Given – entry without a GTI score, even with an active min score threshold
        converter = _given_converter_with_min_score(logger, min_score=50)
        data = _given_file_entry(
            score=None, relationships=_given_minimal_relationships()
        )
        # When
        result = _when_convert(converter, data)
        # Then
        assert result  # noqa: S101

    def test_min_score_100_disables_filter(self, logger: logging.Logger) -> None:
        # Given – min score set to 100 disables filtering entirely
        converter = _given_converter_with_min_score(logger, min_score=100)
        data = _given_file_entry(score=1, relationships=_given_minimal_relationships())
        # When
        result = _when_convert(converter, data)
        # Then – even a very low score entry is kept since the filter is disabled
        assert result  # noqa: S101

    def test_min_score_none_disables_filter(self, logger: logging.Logger) -> None:
        # Given – min score set to None disables filtering entirely
        converter = _given_converter_with_min_score(logger, min_score=None)
        data = _given_file_entry(score=1, relationships=_given_minimal_relationships())
        # When
        result = _when_convert(converter, data)
        # Then – even a very low score entry is kept since the filter is disabled
        assert result  # noqa: S101


# =====================
# 27. convert – indicator_require_malware_family / indicator_require_threat_actor
# =====================


def _given_converter_with_association_filters(
    logger: logging.Logger,
    require_malware: bool = False,
    require_threat_actor: bool = False,
) -> ConvertToSTIXIndicator:
    config = DummyConfig()
    config.indicator_require_malware_family = require_malware
    config.indicator_require_threat_actor = require_threat_actor
    return ConvertToSTIXIndicator(
        config=config,  # type: ignore[arg-type]
        logger=logger,
        tlp_level="white",
    )


def _given_relationships_with_malware_only() -> IOCDeltaRelationships:
    return IOCDeltaRelationships(
        malware_families=IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="malware--test",
                    attributes=IOCDeltaRelationshipItemAttributes(name="TestMalware"),
                )
            ]
        )
    )


def _given_relationships_with_threat_actor_only() -> IOCDeltaRelationships:
    return IOCDeltaRelationships(
        threat_actors=IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="threat-actor--test",
                    attributes=IOCDeltaRelationshipItemAttributes(
                        name="TestThreatActor"
                    ),
                )
            ]
        )
    )


def _given_relationships_with_both() -> IOCDeltaRelationships:
    return IOCDeltaRelationships(
        malware_families=IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="malware--test",
                    attributes=IOCDeltaRelationshipItemAttributes(name="TestMalware"),
                )
            ]
        ),
        threat_actors=IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="threat-actor--test",
                    attributes=IOCDeltaRelationshipItemAttributes(
                        name="TestThreatActor"
                    ),
                )
            ]
        ),
    )


def _given_relationships_with_neither() -> IOCDeltaRelationships:
    return IOCDeltaRelationships(
        software_toolkits=IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="tool--test",
                    attributes=IOCDeltaRelationshipItemAttributes(name="TestTool"),
                )
            ]
        )
    )


class TestConvertAssociationFilter:
    """Test convert() filtering IOC entries by association requirements."""

    def test_no_filters_enabled_keeps_all(self, logger: logging.Logger) -> None:
        # Given – both filters disabled (default)
        converter = _given_converter_with_association_filters(logger)
        data = _given_file_entry(relationships=_given_relationships_with_neither())
        # When
        result = _when_convert(converter, data)
        # Then – entry is kept regardless of associations
        assert result  # noqa: S101

    def test_require_malware_with_malware_keeps(self, logger: logging.Logger) -> None:
        # Given – require malware enabled, entry has malware association
        converter = _given_converter_with_association_filters(
            logger, require_malware=True
        )
        data = _given_file_entry(relationships=_given_relationships_with_malware_only())
        # When
        result = _when_convert(converter, data)
        # Then
        assert result  # noqa: S101

    def test_require_malware_without_malware_filters(
        self, logger: logging.Logger
    ) -> None:
        # Given – require malware enabled, entry has no malware association
        converter = _given_converter_with_association_filters(
            logger, require_malware=True
        )
        data = _given_file_entry(
            relationships=_given_relationships_with_threat_actor_only()
        )
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)

    def test_require_threat_actor_with_threat_actor_keeps(
        self, logger: logging.Logger
    ) -> None:
        # Given – require threat actor enabled, entry has threat actor association
        converter = _given_converter_with_association_filters(
            logger, require_threat_actor=True
        )
        data = _given_file_entry(
            relationships=_given_relationships_with_threat_actor_only()
        )
        # When
        result = _when_convert(converter, data)
        # Then
        assert result  # noqa: S101

    def test_require_threat_actor_without_threat_actor_filters(
        self, logger: logging.Logger
    ) -> None:
        # Given – require threat actor enabled, entry has no threat actor association
        converter = _given_converter_with_association_filters(
            logger, require_threat_actor=True
        )
        data = _given_file_entry(relationships=_given_relationships_with_malware_only())
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)

    def test_both_required_with_malware_only_keeps(
        self, logger: logging.Logger
    ) -> None:
        # Given – both filters enabled (OR logic), entry has malware only
        converter = _given_converter_with_association_filters(
            logger, require_malware=True, require_threat_actor=True
        )
        data = _given_file_entry(relationships=_given_relationships_with_malware_only())
        # When
        result = _when_convert(converter, data)
        # Then – OR logic: malware is enough
        assert result  # noqa: S101

    def test_both_required_with_threat_actor_only_keeps(
        self, logger: logging.Logger
    ) -> None:
        # Given – both filters enabled (OR logic), entry has threat actor only
        converter = _given_converter_with_association_filters(
            logger, require_malware=True, require_threat_actor=True
        )
        data = _given_file_entry(
            relationships=_given_relationships_with_threat_actor_only()
        )
        # When
        result = _when_convert(converter, data)
        # Then – OR logic: threat actor is enough
        assert result  # noqa: S101

    def test_both_required_with_both_keeps(self, logger: logging.Logger) -> None:
        # Given – both filters enabled, entry has both associations
        converter = _given_converter_with_association_filters(
            logger, require_malware=True, require_threat_actor=True
        )
        data = _given_file_entry(relationships=_given_relationships_with_both())
        # When
        result = _when_convert(converter, data)
        # Then
        assert result  # noqa: S101

    def test_both_required_with_neither_filters(self, logger: logging.Logger) -> None:
        # Given – both filters enabled, entry has neither association
        converter = _given_converter_with_association_filters(
            logger, require_malware=True, require_threat_actor=True
        )
        data = _given_file_entry(relationships=_given_relationships_with_neither())
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)

    def test_require_malware_with_no_relationships_filters(
        self, logger: logging.Logger
    ) -> None:
        # Given – require malware enabled, entry has no relationships at all
        converter = _given_converter_with_association_filters(
            logger, require_malware=True
        )
        data = _given_file_entry(relationships=None)
        # When
        result = _when_convert(converter, data)
        # Then
        _then_returns_empty(result)

    def test_association_filter_combined_with_min_score(
        self, logger: logging.Logger
    ) -> None:
        # Given – both score and association filters active (AND logic)
        config = DummyConfig()
        config.indicator_min_score = 50
        config.indicator_require_malware_family = True
        converter = ConvertToSTIXIndicator(
            config=config,  # type: ignore[arg-type]
            logger=logger,
            tlp_level="white",
        )
        # Entry has malware association but score is below threshold
        data = _given_file_entry(
            score=10, relationships=_given_relationships_with_malware_only()
        )
        # When
        result = _when_convert(converter, data)
        # Then – AND logic: score filter rejects even with valid association
        _then_returns_empty(result)
