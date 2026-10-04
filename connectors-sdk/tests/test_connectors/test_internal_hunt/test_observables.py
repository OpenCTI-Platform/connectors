# pragma: no cover
# type: ignore
"""Tests of the observable extraction from hunt results."""

import pytest
from connectors_sdk.connectors.internal_hunt import (
    HuntEvent,
    ObservableValue,
    extract_observables,
    is_public_domain,
    is_public_ip,
    to_observable_model,
)
from connectors_sdk.connectors.internal_hunt.observables import (
    field_tokens,
    observables_from_value,
)
from connectors_sdk.models import (
    URL,
    DomainName,
    EmailAddress,
    File,
    Hostname,
    IPV4Address,
    IPV6Address,
    MACAddress,
    Reference,
    UserAccount,
)
from connectors_sdk.models.enums import HashAlgorithm

ALL_TYPES = [
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Url",
    "StixFile",
    "Email-Addr",
    "Hostname",
    "User-Account",
    "Mac-Addr",
]
MD5 = "d41d8cd98f00b204e9800998ecf8427f"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize(
    "field, expected",
    [
        ("DestinationIp", {"destination", "ip", "destinationip"}),
        ("SenderIPv4", {"sender", "ipv4", "senderipv4"}),
        ("dns.question.name", {"dns", "question", "name"}),
        ("src_ip", {"src", "ip", "srcip"}),
        ("RemoteAddressIP4", {"remote", "address", "ip4", "remoteaddressip4"}),
    ],
)
def test_field_tokens(field, expected):
    # Given/When/Then field names are split into lowercase tokens
    assert field_tokens(field) == expected


def test_public_ip_and_domain_filters():
    # Given/When/Then only internet infrastructure passes the filters
    assert is_public_ip("8.8.8.8") == "IPv4-Addr"
    assert is_public_ip("2001:4860:4860::8888") == "IPv6-Addr"
    assert is_public_ip("10.0.0.1") is None
    assert is_public_ip("not-an-ip") is None
    assert is_public_domain("Evil.Example.ORG.") is True
    assert is_public_domain("dc01.corp") is False
    assert is_public_domain("1.2.3.4") is False
    assert is_public_domain("single") is False


def test_extract_observables_from_telemetry_fields():
    # Given telemetry events with network, DNS, URL, email, hash and host fields
    events = [
        HuntEvent(
            fields={
                "DestinationIp": "8.8.8.8",
                "SourceIp": "10.0.0.5",
                "dns.question.name": "C2.Evil.com",
                "url.full": "https://c2.evil.com/beacon?id=1",
                "url.original": "http://192.168.1.10/internal",
                "SenderFromAddress": "phish@evil.com",
                "RecipientEmailAddress": "alice@corp.local",
                "Hashes": f"SHA1={SHA1},MD5={MD5},SHA256={SHA256},IMPHASH={MD5}",
                "process.hash.sha256": SHA256.upper(),
                "host.name": "WS01.corp.local",
                "user.name": "alice",
                "mac": "AA-BB-CC-DD-EE-FF",
                "dest": "1.1.1.1",
                "CommandLine": "ping 9.9.9.9",
                "src_ip": ["8.8.8.8", "2001:4860:4860::8888"],
            }
        ),
        HuntEvent(fields={"DestinationIp": "8.8.8.8", "dns.question.name": "10.1.1.1"}),
    ]

    # When every supported type is allowed
    observables = extract_observables(events, ALL_TYPES)
    found = {(o.observable_type, o.value): o for o in observables}

    # Then public IOCs are extracted and normalized, internal values are dropped,
    # and a value found in several fields of one event counts once for that event
    assert found[("IPv4-Addr", "8.8.8.8")].count == 2
    assert found[("IPv4-Addr", "1.1.1.1")].count == 1
    assert ("IPv4-Addr", "10.0.0.5") not in found
    assert ("IPv4-Addr", "1.1.1.1") in found
    assert ("IPv4-Addr", "9.9.9.9") not in found
    assert ("IPv6-Addr", "2001:4860:4860::8888") in found
    assert ("Domain-Name", "c2.evil.com") in found
    assert ("Url", "https://c2.evil.com/beacon?id=1") in found
    assert ("Email-Addr", "phish@evil.com") in found
    assert ("Email-Addr", "alice@corp.local") not in found
    assert found[("StixFile", SHA256.lower())].hash_algorithm == HashAlgorithm.SHA256
    assert found[("StixFile", SHA1)].hash_algorithm == HashAlgorithm.SHA1
    assert found[("StixFile", MD5)].hash_algorithm == HashAlgorithm.MD5
    assert ("Hostname", "ws01.corp.local") in found
    assert ("User-Account", "alice") in found
    assert ("Mac-Addr", "aa:bb:cc:dd:ee:ff") in found
    assert observables[0].value == "8.8.8.8"


def test_extract_observables_respects_allowed_types_explicit_fields_and_cap():
    # Given events with a field only known through an explicit mapping
    events = [
        HuntEvent(fields={"RemoteHost": "evil.com", "user.name": "alice"}),
        HuntEvent(fields={"RemoteHost": "bad.org", "weird": "x"}),
        HuntEvent(fields={"RemoteHost": "evil.com"}),
    ]

    # When only domains are allowed and at most one observable is returned
    observables = extract_observables(
        events, ["Domain-Name"], {"remotehost": "Domain-Name"}, max_items=1
    )

    # Then the most frequent allowed observable is returned
    assert observables == [ObservableValue("Domain-Name", "evil.com", None, 2)]
    assert extract_observables(events, []) == []
    assert extract_observables(events, ["Domain-Name"], max_items=0) == []


@pytest.mark.parametrize(
    "observable_type, value, expected",
    [
        ("Url", "ftp://", []),
        ("Url", "http://[::1", []),
        ("Url", "mailto:x@evil.com", []),
        ("Email-Addr", "not an email", []),
        ("StixFile", "zz" * 16, []),
        ("StixFile", "abc", []),
        ("Hostname", "bad host", []),
        ("User-Account", "a\nb", []),
        ("Mac-Addr", "aa:bb", []),
        ("Unknown", "x", []),
    ],
)
def test_observables_from_value_rejects_invalid_values(
    observable_type, value, expected
):
    # Given/When/Then invalid values give no observable
    assert observables_from_value(observable_type, value) == expected


def test_observables_from_value_uses_hash_length_without_hint():
    # Given/When/Then a hash without algorithm hint is typed by its length
    assert observables_from_value("StixFile", SHA1) == [
        ObservableValue("StixFile", SHA1, HashAlgorithm.SHA1)
    ]


@pytest.mark.parametrize(
    "observable, model_type",
    [
        (ObservableValue("IPv4-Addr", "8.8.8.8"), IPV4Address),
        (ObservableValue("IPv6-Addr", "2001:4860:4860::8888"), IPV6Address),
        (ObservableValue("Domain-Name", "evil.com"), DomainName),
        (ObservableValue("Url", "https://evil.com/"), URL),
        (ObservableValue("Email-Addr", "a@evil.com"), EmailAddress),
        (ObservableValue("StixFile", MD5, HashAlgorithm.MD5), File),
        (ObservableValue("StixFile", SHA256), File),
        (ObservableValue("Hostname", "ws01"), Hostname),
        (ObservableValue("User-Account", "alice"), UserAccount),
        (ObservableValue("Mac-Addr", "aa:bb:cc:dd:ee:ff"), MACAddress),
    ],
)
def test_to_observable_model(observable, model_type):
    # Given the hunt author and markings
    author = Reference(id="identity--7b82b010-b1c0-4dae-981f-7756374a17df")
    markings = [
        Reference(id="marking-definition--f88d31f6-486f-44da-b317-01333bde0b82")
    ]

    # When the observable model is built
    model = to_observable_model(observable, author, markings)

    # Then it carries the author and the markings
    stix = model.to_stix2_object()
    assert isinstance(model, model_type)
    assert stix["x_opencti_created_by_ref"] == author.id
    assert stix["object_marking_refs"] == [markings[0].id]


def test_to_observable_model_without_markings_and_unknown_type():
    # Given/When an observable without markings is built
    model = to_observable_model(ObservableValue("IPv4-Addr", "8.8.8.8"), None, [])

    # Then no marking is set, and unknown types are rejected
    assert model.markings is None
    with pytest.raises(ValueError, match="Unsupported observable type"):
        to_observable_model(ObservableValue("Process", "x"), None, [])
