from modat_client.models import ModatHost


def test_empty_record_yields_defaults():
    host = ModatHost.model_validate({})
    assert host.asn.number is None
    assert host.asn.org is None
    assert host.geo.country_name is None
    assert host.fqdns == []
    assert host.services == []
    assert host.cves == []
    assert host.tags == []
    assert host.is_anycast is False


def test_lenient_parsing_tolerates_nulls_and_junk():
    """The model must never reject a real (partial/messy) host record: nulls
    become empty containers, malformed list entries are dropped, and unknown
    fields are ignored."""
    host = ModatHost.model_validate(
        {
            "asn": None,  # null where an object is expected
            "geo": None,
            "fqdns": ["good.example", "", 123, None],  # mixed junk
            "tags": ["ok", 5, None],
            "services": [
                "not-a-service",  # dropped (not a dict)
                {
                    "transport": "tcp",
                    "tls": None,
                    "ports": None,
                    "cves": [{"id": "CVE-1", "cvss": "9.8", "is_kev": 1}, "junk"],
                },
            ],
            "cves": [{"id": "CVE-2", "cvss": 7}, "junk"],
            "is_anycast": None,
            "unknown_field": {"nested": True},  # ignored
        }
    )

    assert host.asn.number is None
    assert host.fqdns == ["good.example"]  # empty/non-str dropped
    assert host.tags == ["ok"]
    assert host.is_anycast is False
    assert len(host.services) == 1  # non-dict entry dropped

    svc = host.services[0]
    assert svc.transport == "tcp"
    assert svc.tls is None
    assert svc.ports == []  # null normalised to []
    assert len(svc.cves) == 1  # "junk" dropped
    assert svc.cves[0].id == "CVE-1"
    assert svc.cves[0].cvss == 9.8  # numeric string coerced
    assert svc.cves[0].is_kev is True  # 1 -> True

    assert len(host.cves) == 1
    assert host.cves[0].cvss == 7.0


def test_nested_blobs_kept_as_dicts_for_helpers():
    """Polymorphic leaf blobs (DNs, SAN extensions, fingerprint entries) stay as
    plain dicts/Any so the existing ModatUtils helpers can parse them."""
    host = ModatHost.model_validate(
        {
            "services": [
                {
                    "fingerprints": {"service": {"name": "nginx", "version": "1.25"}},
                    "tls": {
                        "issuer": {"common_name": ["Example CA"]},
                        "extensions": {"subject_alt_name": {"dns": ["example.org"]}},
                    },
                }
            ]
        }
    )
    svc = host.services[0]
    assert svc.fingerprints.service == {"name": "nginx", "version": "1.25"}
    assert svc.tls.issuer == {"common_name": ["Example CA"]}
    assert svc.tls.extensions["subject_alt_name"]["dns"] == ["example.org"]


def test_scalar_type_surprises_coerce_instead_of_raising():
    """Wrong-typed scalars (string CVSS, numeric serial, string bool, etc.) must
    coerce to None/str/bool rather than abort the whole host parse."""
    host = ModatHost.model_validate(
        {
            "asn": {"number": "13335", "org": 12345},  # number as str, org as int
            "geo": {"country_iso_code": 840},  # iso code as int
            "is_anycast": "false",  # string bool
            "services": [
                {
                    "last_scanned_port": "unknown",  # non-numeric port
                    "http": {"status_code": "200"},  # numeric-string status
                    "tls": {"serial_number": 12345, "is_self_signed": "true"},
                    "cves": [{"id": "CVE-1", "cvss": "N/A", "is_kev": "false"}],
                }
            ],
            "cves": [{"id": "CVE-2", "cvss": "", "is_kev": "true"}],
        }
    )
    assert host.asn.number == 13335  # "13335" -> 13335
    assert host.asn.org == "12345"  # 12345 -> "12345"
    assert host.geo.country_iso_code == "840"
    assert host.is_anycast is False  # "false" must NOT be truthy
    svc = host.services[0]
    assert svc.last_scanned_port is None  # "unknown" -> None, not a raise
    assert svc.http.status_code == 200  # "200" -> 200
    assert svc.tls.serial_number == "12345"
    assert svc.tls.is_self_signed is True
    assert svc.cves[0].cvss is None  # "N/A" -> None
    assert svc.cves[0].is_kev is False  # "false" -> False
    assert host.cves[0].cvss is None  # "" -> None
    assert host.cves[0].is_kev is True


def test_model_never_raises_on_arbitrary_garbage():
    """Structurally wrong shapes must not raise — they degrade to defaults."""
    for junk in (
        {},
        {"asn": "x"},
        {"services": "nope"},
        {"cves": {"not": "a list"}},
        {"geo": [1, 2]},
        {"fqdns": "a.com"},
        {"is_anycast": None},
        {"services": ["junk", 5, None]},
    ):
        ModatHost.model_validate(junk)  # must not raise
