import pytest
from connector.hive_observable_transform import (
    HiveObservableTransform,
    UnsupportedIndicatorTypeError,
)

MARKINGS = []
CREATED_BY_REF = "identity--a5f78c07-79e2-4e8a-b1dd-fa3e5e5f1a5c"


def make_obs(data_type, data, **kwargs):
    return {"dataType": data_type, "data": data, "ioc": False, "tags": [], **kwargs}


@pytest.mark.parametrize(
    "data_type,data,expected_stix_type",
    [
        ("ipv4", "192.168.1.1", "ipv4-addr"),
        ("ip", "10.0.0.1", "ipv4-addr"),
        ("ip", "2001:db8::1", "ipv6-addr"),
        ("ipv6", "2001:db8::1", "ipv6-addr"),
        ("fqdn", "example.com", "domain-name"),
        ("domain", "evil.com", "domain-name"),
        ("url", "https://example.com/path", "url"),
        ("uri_path", "https://example.com/api", "url"),
        ("mail", "user@example.com", "email-addr"),
        ("email_address", "admin@example.com", "email-addr"),
        ("mail_subject", "Phishing email subject", "email-message"),
        ("email_subject", "Urgent: click here", "email-message"),
        ("mail-subject", "Re: invoice", "email-message"),
        ("registry", "HKLM\\Software\\Microsoft", "windows-registry-key"),
        ("registry_key", "HKLM\\Run\\evil", "windows-registry-key"),
        ("other", "some text value", "text"),
        ("regexp", ".*evil.*", "text"),
        ("user-agent", "Mozilla/5.0 Malicious", "user-agent"),
        ("user_agent", "curl/7.68.0", "user-agent"),
        ("filename", "malware.exe", "file"),
    ],
)
def test_observable_type_mapping(data_type, data, expected_stix_type):
    obs = make_obs(data_type, data)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == expected_stix_type


def test_hash_md5():
    obs = make_obs("hash", "a" * 32)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.data_type == "file_md5"
    assert transform.stix_observable.type == "file"
    assert "MD5" in transform.stix_observable.hashes


def test_hash_sha1():
    obs = make_obs("hash", "b" * 40)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.data_type == "file_sha1"
    assert "SHA-1" in transform.stix_observable.hashes


def test_hash_sha256():
    obs = make_obs("hash", "c" * 64)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.data_type == "file_sha256"
    assert "SHA-256" in transform.stix_observable.hashes


def test_file_md5_direct():
    obs = make_obs("file_md5", "a" * 32)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == "file"


def test_file_sha1_direct():
    obs = make_obs("file_sha1", "b" * 40)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == "file"


def test_file_sha256_direct():
    obs = make_obs("file_sha256", "c" * 64)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == "file"


def test_file_with_attachment():
    obs = make_obs(
        "file",
        "attachment",
        attachment={"hashes": ["a" * 32], "names": "malware.exe"},
    )
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == "file"


def test_cve_observable():
    obs = make_obs("cve", "CVE-2021-44228")
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == "vulnerability"


def test_identity_individual():
    obs = make_obs("identity", "John Doe")
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == "identity"
    assert transform.stix_observable.identity_class == "individual"


def test_identity_system():
    obs = make_obs("system", "webserver01")
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == "identity"
    assert transform.stix_observable.identity_class == "system"


def test_organization():
    obs = make_obs("organisation", "Acme Corp")
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == "identity"
    assert transform.stix_observable.identity_class == "organization"


def test_autonomous_system():
    obs = make_obs("autonomous-system", 12345)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert transform.stix_observable.type == "autonomous-system"


def test_ioc_flag_sets_high_score():
    obs = make_obs("ipv4", "1.2.3.4", ioc=True)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    props = transform.create_custom_properties()
    assert props["x_opencti_score"] == 80


def test_non_ioc_sets_low_score():
    obs = make_obs("ipv4", "1.2.3.4", ioc=False)
    transform = HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    props = transform.create_custom_properties()
    assert props["x_opencti_score"] == 50


def test_unsupported_type_raises():
    obs = make_obs("totally-unknown-type-xyz", "somevalue")
    with pytest.raises(UnsupportedIndicatorTypeError) as exc_info:
        HiveObservableTransform(obs, MARKINGS, CREATED_BY_REF)
    assert "totally-unknown-type-xyz" in str(exc_info.value)


def test_unsupported_indicator_type_error_attributes():
    err = UnsupportedIndicatorTypeError("my-type")
    assert err.indicator_type == "my-type"
    assert "my-type" in str(err)
