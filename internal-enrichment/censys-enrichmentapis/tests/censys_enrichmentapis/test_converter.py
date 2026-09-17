import stix2
from censys_enrichmentapis.converters.domain import DomainConverter
from censys_enrichmentapis.converters.host import HostConverter
from censys_platform import (
    Attribute,
    Certificate,
    CertificateParsed,
    DistinguishedName,
    EndpointScanState,
    HostEnrichment,
    Label,
    Signature,
    Threat,
    ValidityPeriod,
    Vuln,
    Webproperty,
)


def test_converter_ipv4(host_ipv4: HostEnrichment) -> None:
    stix_objects = [
        object_.to_stix2_object()
        for object_ in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="1.1.1.1"),
            data=host_ipv4,
        )
    ]

    author_id = "identity--169b39b7-ea64-5a16-bb05-ed1045005079"
    marking_id = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ip_id = "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"

    assert len(stix_objects) == 21

    author = next(object_ for object_ in stix_objects if object_.id == author_id)
    assert author.type == "identity"
    assert author.name == "Censys EnrichmentAPIs Connector"
    assert author.identity_class == "organization"

    marking = next(object_ for object_ in stix_objects if object_.id == marking_id)
    assert marking.type == "marking-definition"
    assert marking.definition == {"statement": "custom"}
    assert marking.definition_type == "statement"
    assert marking.x_opencti_definition == "TLP:CLEAR"
    assert marking.x_opencti_definition_type == "TLP"

    for object_ in stix_objects[2:]:
        assert author_id in {
            getattr(object_, "created_by_ref", None),
            getattr(object_, "x_opencti_created_by_ref", None),
        }
        assert object_.object_marking_refs == [marking_id]

    locations = {
        object_.id: object_ for object_ in stix_objects if object_.type == "location"
    }
    assert set(locations) == {
        "location--718026de-1217-54e3-9915-ebddd72ffc2b",
        "location--834c5189-3715-561b-b68a-e835372d05ff",
        "location--50b4cef5-9f48-5ae6-9777-8e1217b8f83d",
        "location--6004efb1-d850-551c-af0d-4717244377a8",
    }
    assert locations["location--718026de-1217-54e3-9915-ebddd72ffc2b"].city == "Brisbane"
    assert locations["location--834c5189-3715-561b-b68a-e835372d05ff"].region == "Oceania"
    administrative_area = locations["location--50b4cef5-9f48-5ae6-9777-8e1217b8f83d"]
    assert administrative_area.administrative_area == "Queensland"
    assert (administrative_area.latitude, administrative_area.longitude) == (-27.47, 153.02)
    assert locations["location--6004efb1-d850-551c-af0d-4717244377a8"].country == "Australia"

    hostnames = {
        object_.id: object_ for object_ in stix_objects if object_.type == "hostname"
    }
    assert {object_.value for object_ in hostnames.values()} == {
        "guestcontroller.sa.gov.au",
        "matrix.cyops.cloud",
    }

    organization = next(
        object_
        for object_ in stix_objects
        if object_.id == "identity--a7d63be9-7173-560e-9723-a5040d771c2c"
    )
    assert organization.name == "CLOUDFLARENET"
    assert organization.identity_class == "organization"

    autonomous_system = next(
        object_
        for object_ in stix_objects
        if object_.id == "autonomous-system--0204c07d-e4dd-5f14-a3d5-c93cb1c5a9fc"
    )
    assert autonomous_system.name == "CLOUDFLARENET"
    assert autonomous_system.number == 13335
    assert autonomous_system.x_opencti_description == "CLOUDFLARENET"

    relationships = {
        (object_.relationship_type, str(object_.source_ref), str(object_.target_ref))
        for object_ in stix_objects
        if object_.type == "relationship"
    }
    assert relationships == {
        ("located-at", ip_id, "location--718026de-1217-54e3-9915-ebddd72ffc2b"),
        ("located-at", ip_id, "location--834c5189-3715-561b-b68a-e835372d05ff"),
        ("located-at", ip_id, "location--50b4cef5-9f48-5ae6-9777-8e1217b8f83d"),
        ("located-at", ip_id, "location--6004efb1-d850-551c-af0d-4717244377a8"),
        ("resolves-to", "hostname--2aa1a527-f7f9-59c6-aa42-716270bccb27", ip_id),
        ("resolves-to", "hostname--21f6b21c-7cae-55af-b29b-54628a2c56f4", ip_id),
        ("related-to", ip_id, "identity--a7d63be9-7173-560e-9723-a5040d771c2c"),
        ("belongs-to", ip_id, "autonomous-system--0204c07d-e4dd-5f14-a3d5-c93cb1c5a9fc"),
        (
            "related-to",
            "autonomous-system--0204c07d-e4dd-5f14-a3d5-c93cb1c5a9fc",
            "identity--a7d63be9-7173-560e-9723-a5040d771c2c",
        ),
        (
            "related-to",
            "autonomous-system--0204c07d-e4dd-5f14-a3d5-c93cb1c5a9fc",
            "location--6004efb1-d850-551c-af0d-4717244377a8",
        ),
    }

    note = next(object_ for object_ in stix_objects if object_.type == "note")
    assert note.abstract == "Service information on port 443 (Unknown)"
    assert note.authors == ["Censys EnrichmentAPIs Connector"]
    assert "| Key | Value |" in note.content
    assert "| Last Scan Time | 2025-11-03T12:35:48Z |" in note.content
    assert "| Label 1 | REMOTE_ACCESS |" in note.content
    assert note.object_refs == [ip_id]


def test_converter_domain_adds_web_property_markdown_note() -> None:
    domain = stix2.DomainName(value="example.com")
    web_property = Webproperty(
        hostname="example.com",
        port=443,
        endpoints=[EndpointScanState(endpoint_type="PLEX_MEDIA_SERVER")],
        scan_time="2026-04-09T06:26:02.631Z",
        labels=[Label(value="IOT")],
        threats=[Threat(name="Fake Captcha")],
        vulns=[Vuln(name="CVE-2025-1695")],
        software=[
            Attribute(vendor="imperva", product="securesphere", version="1.27.1.1")
        ],
        cert=Certificate(
            fingerprint_sha256="cd44421bee6d84a57373f36853175cc3ce0c2437c8a3957a55318d483e90f0ed",
            names=["www.example.com"],
            parsed=CertificateParsed(
                subject_dn="C=US, CN=example.com",
                issuer_dn="C=US, O=Example CA",
                subject=DistinguishedName(common_name=["example.com"]),
                validity_period=ValidityPeriod(
                    not_before="2025-12-01T06:47:51.000Z",
                    not_after="2029-08-09T06:47:51.000Z",
                ),
                signature=Signature(self_signed=True),
            ),
        ),
    )

    converter = DomainConverter()
    stix_objects = [
        object_.to_stix2_object()
        for object_ in converter.to_stix(
            observable=domain,
            data={"web_properties": [web_property], "certs": []},
        )
    ]

    assert converter.primary_observable_labels == ["Censys_Threat_Fake_Captcha"]
    note = next(object_ for object_ in stix_objects if object_.type == "note")
    assert note.abstract == "Censys web property `example.com`:443"
    assert note.object_refs == [domain.id]
    assert note.labels == ["Censys_Threat_Fake_Captcha"]
    assert note.content.startswith(
        "[https://platform.censys.io/web/example.com:443]"
        "(https://platform.censys.io/web/example.com:443)\n\n"
    )
    assert "| Key | Value |" in note.content
    assert "| web.hostname | `example.com` |" in note.content
    assert "| web.port | `443` |" in note.content
    assert "| web.endpoints.endpoint_type | `PLEX_MEDIA_SERVER` |" in note.content
    assert "| web.scan_time | `2026-04-09T06:26:02.631Z` |" in note.content
    assert "| web.labels.value | `IOT` |" in note.content
    assert "| web.threats.name | `Fake Captcha` |" in note.content
    assert "| web.vulns.name | `CVE-2025-1695` |" in note.content
    assert "| web.software.vendor | `imperva` |" in note.content
    assert "| web.software.product | `securesphere` |" in note.content
    assert "| web.software.version | `1.27.1.1` |" in note.content
    assert (
        "| web.cert.fingerprint_sha256 | "
        "`cd44421bee6d84a57373f36853175cc3ce0c2437c8a3957a55318d483e90f0ed` |"
        in note.content
    )
    assert "| web.cert.parsed.subject_dn | `C=US, CN=example.com` |" in note.content
    assert "| web.cert.parsed.issuer_dn | `C=US, O=Example CA` |" in note.content
    assert "| web.cert.parsed.subject.common_name | `example.com` |" in note.content
    assert (
        "| web.cert.parsed.validity_period.not_before | "
        "`2025-12-01T06:47:51.000Z` |" in note.content
    )
    assert (
        "| web.cert.parsed.validity_period.not_after | "
        "`2029-08-09T06:47:51.000Z` |" in note.content
    )
    assert "| web.cert.parsed.signature.self_signed | `true` |" in note.content
    assert "| web.cert.names | `www.example.com` |" in note.content
