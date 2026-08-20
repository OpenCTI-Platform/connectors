import stix2
import stix2.exceptions
from connector.converter_to_stix import ConverterToStix, handle_stix2_error
from pycti import CustomObservableHostname

# ---------------------------------------------------------------------------
# handle_stix2_error decorator
# ---------------------------------------------------------------------------


def test_handle_stix2_error_passes_through_on_success(converter):
    result = converter.create_mitre_attack_pattern("T1059")
    assert result is not None


def test_handle_stix2_error_returns_none_on_stix_error(mock_helper, mock_config):
    class FaultyConverter(ConverterToStix):
        @handle_stix2_error
        def faulty_method(self):
            raise stix2.exceptions.STIXError("forced error")

    conv = FaultyConverter(mock_helper, mock_config, stix2.TLP_RED)
    result = conv.faulty_method()
    assert result is None
    mock_helper.connector_logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# create_author_identity
# ---------------------------------------------------------------------------


def test_create_author_identity_returns_identity():
    author = ConverterToStix.create_author_identity(
        name="Test Connector",
        identity_class="organization",
        description="A test connector",
    )
    assert isinstance(author, stix2.Identity)
    assert author.name == "Test Connector"
    assert author.identity_class == "organization"


def test_create_author_identity_is_deterministic():
    author1 = ConverterToStix.create_author_identity(
        name="Test", identity_class="organization"
    )
    author2 = ConverterToStix.create_author_identity(
        name="Test", identity_class="organization"
    )
    assert author1.id == author2.id


# ---------------------------------------------------------------------------
# create_incident
# ---------------------------------------------------------------------------

_BASE_ALERT = {
    "title": "Malware Detected",
    "createdDateTime": "2024-01-15T10:30:00Z",
    "lastUpdateDateTime": "2024-01-15T11:00:00Z",
    "category": "malware",
    "description": "A test alert",
    "recommendedActions": "Isolate device",
    "alertWebUrl": "https://defender.microsoft.com/alert/123",
    "id": "alert-123",
    "severity": "high",
}


def test_create_incident_returns_stix_incident(converter):
    result = converter.create_incident(_BASE_ALERT)
    assert result is not None
    assert isinstance(result, stix2.Incident)
    assert result.name == "Malware Detected"
    assert result.labels == ["malware"]


def test_create_incident_no_category_produces_no_labels(converter):
    alert = {**_BASE_ALERT, "category": None}
    result = converter.create_incident(alert)
    assert result is not None
    assert getattr(result, "labels", None) is None


def test_create_incident_is_deterministic(converter):
    r1 = converter.create_incident(_BASE_ALERT)
    r2 = converter.create_incident(_BASE_ALERT)
    assert r1.id == r2.id


# ---------------------------------------------------------------------------
# create_custom_case_incident
# ---------------------------------------------------------------------------

_BASE_INCIDENT = {
    "displayName": "Test Case",
    "createdDateTime": "2024-01-15T10:00:00Z",
    "classification": "truePositive",
    "determination": "malware",
    "severity": "high",
    "id": "incident-1",
    "incidentWebUrl": "https://example.com/incident/1",
}


def test_create_custom_case_incident(converter):
    stix_incident = converter.create_incident(_BASE_ALERT)
    result = converter.create_custom_case_incident(_BASE_INCIDENT, [stix_incident])
    assert result is not None
    assert result.name == "Test Case"


# ---------------------------------------------------------------------------
# create_evidence_user_account
# ---------------------------------------------------------------------------


def test_create_evidence_user_account_valid(converter):
    evidence = {"userAccount": {"accountName": "testuser", "displayName": "Test User"}}
    result = converter.create_evidence_user_account(evidence)
    assert result is not None
    assert isinstance(result, stix2.UserAccount)
    assert result.account_login == "testuser"


def test_create_evidence_user_account_no_user_account_key(converter):
    result = converter.create_evidence_user_account({})
    assert result is None


def test_create_evidence_user_account_not_a_dict(converter):
    result = converter.create_evidence_user_account({"userAccount": "not-a-dict"})
    assert result is None


def test_create_evidence_user_account_both_names_missing(converter):
    result = converter.create_evidence_user_account({"userAccount": {}})
    assert result is None


def test_create_evidence_user_account_only_display_name(converter):
    evidence = {"userAccount": {"displayName": "John Doe"}}
    result = converter.create_evidence_user_account(evidence)
    assert result is not None
    assert result.display_name == "John Doe"


# ---------------------------------------------------------------------------
# create_evidence_ipv4 / ipv6
# ---------------------------------------------------------------------------


def test_create_evidence_ipv4(converter):
    result = converter.create_evidence_ipv4({"ipAddress": "192.168.1.100"})
    assert result is not None
    assert isinstance(result, stix2.IPv4Address)
    assert result.value == "192.168.1.100"


def test_create_evidence_ipv6(converter):
    result = converter.create_evidence_ipv6({"ipAddress": "2001:db8::1"})
    assert result is not None
    assert isinstance(result, stix2.IPv6Address)
    assert result.value == "2001:db8::1"


# ---------------------------------------------------------------------------
# create_evidence_url
# ---------------------------------------------------------------------------


def test_create_evidence_url(converter):
    result = converter.create_evidence_url(
        {"url": "http://malicious.example.com/payload"}
    )
    assert result is not None
    assert isinstance(result, stix2.URL)
    assert result.value == "http://malicious.example.com/payload"


# ---------------------------------------------------------------------------
# create_evidence_file
# ---------------------------------------------------------------------------


def test_create_evidence_file_with_dict_hashes(converter):
    evidence = {
        "imageFile": {
            "fileName": "malware.exe",
            "md5": "a" * 32,
            "sha1": "b" * 40,
            "sha256": "c" * 64,
            "fileSize": 1024,
            "filePath": "C:\\temp",
        }
    }
    directory = stix2.Directory(path="C:\\temp")
    result = converter.create_evidence_file(evidence, directory)
    assert result is not None
    assert isinstance(result, stix2.File)
    assert result.name == "malware.exe"
    assert "MD5" in result.hashes


def test_create_evidence_file_with_str_hash(converter):
    evidence = {"value": "a" * 64, "algorithm": "SHA-256"}
    result = converter.create_evidence_file(evidence, None)
    assert result is not None
    assert isinstance(result, stix2.File)


def test_create_evidence_file_duplicate_hash_returns_none(converter):
    hash_val = "a" * 64
    converter.all_hashes.add(hash_val)
    evidence = {"value": hash_val, "algorithm": "SHA-256"}
    result = converter.create_evidence_file(evidence, None)
    assert result is None


def test_create_evidence_file_no_hashes_returns_none(converter):
    evidence = {"imageFile": {"fileName": "nofile.exe"}}
    result = converter.create_evidence_file(evidence, None)
    assert result is None


def test_create_evidence_file_filedetails(converter):
    evidence = {
        "fileDetails": {
            "fileName": "script.ps1",
            "sha256": "d" * 64,
            "filePath": "C:\\scripts",
        }
    }
    directory = stix2.Directory(path="C:\\scripts")
    result = converter.create_evidence_file(evidence, directory)
    assert result is not None
    assert "SHA-256" in result.hashes


# ---------------------------------------------------------------------------
# create_evidence_directory
# ---------------------------------------------------------------------------


def test_create_evidence_directory_with_path(converter):
    result = converter.create_evidence_directory({"filePath": "C:\\Windows\\System32"})
    assert result is not None
    assert isinstance(result, stix2.Directory)
    assert result.path == "C:\\Windows\\System32"


def test_create_evidence_directory_empty_path_returns_none(converter):
    result = converter.create_evidence_directory({"filePath": ""})
    assert result is None


def test_create_evidence_directory_missing_path_returns_none(converter):
    result = converter.create_evidence_directory({})
    assert result is None


# ---------------------------------------------------------------------------
# create_evidence_identity_system
# ---------------------------------------------------------------------------


def test_create_evidence_identity_system_with_dns(converter):
    result = converter.create_evidence_identity_system(
        {"deviceDnsName": "workstation.example.com"}
    )
    assert result is not None
    assert isinstance(result, stix2.Identity)
    assert result.name == "workstation.example.com"
    assert result.identity_class == "system"


def test_create_evidence_identity_system_no_dns_returns_none(converter):
    result = converter.create_evidence_identity_system({})
    assert result is None
    converter.helper.connector_logger.warning.assert_called()


# ---------------------------------------------------------------------------
# create_evidence_custom_observable_hostname
# ---------------------------------------------------------------------------


def test_create_evidence_custom_observable_hostname_with_dns(converter):
    result = converter.create_evidence_custom_observable_hostname(
        {"deviceDnsName": "workstation.example.com"}
    )
    assert result is not None
    assert isinstance(result, CustomObservableHostname)


def test_create_evidence_custom_observable_hostname_no_dns_returns_none(converter):
    result = converter.create_evidence_custom_observable_hostname({})
    assert result is None
    converter.helper.connector_logger.warning.assert_called()


# ---------------------------------------------------------------------------
# create_mitre_attack_pattern
# ---------------------------------------------------------------------------


def test_create_mitre_attack_pattern(converter):
    result = converter.create_mitre_attack_pattern("T1059")
    assert result is not None
    assert isinstance(result, stix2.AttackPattern)
    assert result.name == "T1059"


def test_create_mitre_attack_pattern_is_deterministic(converter):
    r1 = converter.create_mitre_attack_pattern("T1059")
    r2 = converter.create_mitre_attack_pattern("T1059")
    assert r1.id == r2.id


# ---------------------------------------------------------------------------
# create_evidence_malware
# ---------------------------------------------------------------------------


def test_create_evidence_malware_with_sample_refs(converter):
    stix_file = stix2.File(hashes={"MD5": "a" * 32}, name="malware.exe")
    evidence = {
        "name": "WannaCry",
        "createdDateTime": "2024-01-15T10:30:00Z",
        "category": ["ransomware"],
    }
    result = converter.create_evidence_malware(evidence, [stix_file])
    assert result is not None
    assert isinstance(result, stix2.Malware)
    assert result.name == "WannaCry"
    assert result.sample_refs is not None


def test_create_evidence_malware_without_sample_refs(converter):
    evidence = {
        "name": "TestMalware",
        "createdDateTime": "2024-01-15T10:30:00Z",
        "category": ["trojan"],
    }
    result = converter.create_evidence_malware(evidence, [])
    assert result is not None
    assert getattr(result, "sample_refs", None) is None


# ---------------------------------------------------------------------------
# create_relationship
# ---------------------------------------------------------------------------


def test_create_relationship(converter):
    src = converter.create_evidence_ipv4({"ipAddress": "1.2.3.4"})
    tgt = converter.create_incident(_BASE_ALERT)
    result = converter.create_relationship(
        source_id=src.id,
        target_id=tgt.id,
        relationship_type="related-to",
    )
    assert result is not None
    assert isinstance(result, stix2.Relationship)
    assert result.relationship_type == "related-to"
    assert result.source_ref == src.id
    assert result.target_ref == tgt.id


def test_create_relationship_is_deterministic(converter):
    src = converter.create_evidence_ipv4({"ipAddress": "1.2.3.4"})
    tgt = converter.create_incident(_BASE_ALERT)
    r1 = converter.create_relationship(src.id, tgt.id, "related-to")
    r2 = converter.create_relationship(src.id, tgt.id, "related-to")
    assert r1.id == r2.id
