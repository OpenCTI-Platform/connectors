import stix2
from censys_enrichment.client import NVDAffectedSoftware, NVDData, NVDReference
from censys_enrichment.converter import Converter
from censys_platform import (
    Attribute,
    CobaltStrike,
    CobaltStrikeConfig,
    CobaltStrikeHTTPConfig,
    CobaltStrikePostEx,
    Cwe,
    Dcerpc,
    DcerpcEndpoint,
    EndpointScanState,
    Host,
    HostDNS,
    HostDNSReverseResolution,
    Ja4TScanScan,
    JarmScan,
    KEVSource,
    Kev,
    Label,
    Metrics,
    NtlmInfo,
    Risk,
    Service,
    Severity,
    Smb,
    SmbNegotiationLog,
    SSH,
    SSHEndpointID,
    SSHServerHostKey,
    TLS,
    Threat,
    ThreatMalware,
    VersionSelected,
    Vuln,
    Winrm,
)


def test_converter_ipv4(host_ipv4: Host) -> None:
    converter = Converter()

    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="1.1.1.1"),
            data=host_ipv4,
        )
    ]

    # 25 original objects + 1 IP with Censys external reference
    assert len(stix_objects) == 26

    entity = stix_objects[0]
    assert entity.type == "identity"
    assert entity.id == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.name == "Censys Enrichment Connector"
    assert entity.identity_class == "organization"

    entity = stix_objects[1]
    assert entity.definition == {"statement": "custom"}
    assert entity.definition_type == "statement"
    assert entity.id == "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    assert entity.type == "marking-definition"
    assert entity.x_opencti_definition == "TLP:CLEAR"
    assert entity.x_opencti_definition_type == "TLP"

    entity = stix_objects[2]
    assert entity.city == "Brisbane"
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "location--718026de-1217-54e3-9915-ebddd72ffc2b"
    assert entity.name == "Brisbane"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.type == "location"
    assert entity.x_opencti_location_type == "City"

    entity = stix_objects[3]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--f4aae08e-7e20-5607-b995-47abceb18112"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "located-at"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.target_ref == "location--718026de-1217-54e3-9915-ebddd72ffc2b"
    assert entity.type == "relationship"

    entity = stix_objects[4]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "location--834c5189-3715-561b-b68a-e835372d05ff"
    assert entity.name == "Oceania"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.region == "Oceania"
    assert entity.type == "location"
    assert entity.x_opencti_location_type == "Region"

    entity = stix_objects[5]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--d28b46f6-83e9-514c-b60a-3e58fa8e9b0c"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "located-at"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.target_ref == "location--834c5189-3715-561b-b68a-e835372d05ff"
    assert entity.type == "relationship"

    entity = stix_objects[6]
    assert entity.administrative_area == "Queensland"
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "location--50b4cef5-9f48-5ae6-9777-8e1217b8f83d"
    assert entity.latitude == -27.47
    assert entity.longitude == 153.02
    assert entity.name == "Queensland"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.type == "location"
    assert entity.x_opencti_location_type == "Administrative-Area"

    entity = stix_objects[7]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--41053389-821a-5c0d-9cba-1edae577fa0f"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "located-at"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.target_ref == "location--50b4cef5-9f48-5ae6-9777-8e1217b8f83d"
    assert entity.type == "relationship"

    entity = stix_objects[8]
    assert entity.id == "hostname--2aa1a527-f7f9-59c6-aa42-716270bccb27"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.type == "hostname"
    assert entity.value == "guestcontroller.sa.gov.au"
    assert (
        entity.x_opencti_created_by_ref
        == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    )

    entity = stix_objects[9]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--2e421e88-4e89-5f40-bd18-600d41e30756"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "resolves-to"
    assert entity.source_ref == "hostname--2aa1a527-f7f9-59c6-aa42-716270bccb27"
    assert entity.target_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.type == "relationship"

    entity = stix_objects[10]
    assert entity.id == "hostname--21f6b21c-7cae-55af-b29b-54628a2c56f4"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.type == "hostname"
    assert entity.value == "matrix.cyops.cloud"
    assert (
        entity.x_opencti_created_by_ref
        == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    )

    entity = stix_objects[11]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--9bb2de5d-4f5b-543a-a46f-6ed695ea9935"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "resolves-to"
    assert entity.source_ref == "hostname--21f6b21c-7cae-55af-b29b-54628a2c56f4"
    assert entity.target_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.type == "relationship"

    entity = stix_objects[12]
    assert entity.cpe == "cpe:2.3:a:cloudflare:waf:*:*:*:*:*:*:*:*"
    assert entity.id == "software--2a36d04a-16da-557d-9e44-565c085007a4"
    assert entity.name == "cloudflare_waf"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.type == "software"
    assert entity.vendor == "cloudflare"
    assert (
        entity.x_opencti_created_by_ref
        == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    )

    entity = stix_objects[13]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--b5ac0fb1-e0f6-5f5d-9cd7-cbccb14348fb"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "related-to"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.target_ref == "software--2a36d04a-16da-557d-9e44-565c085007a4"
    assert entity.type == "relationship"

    entity = stix_objects[14]
    assert entity.authority_key_identifier == "748580c066c7df37decfbd2937aa031dbeedcd17"
    assert entity.basic_constraints in ('{"is_ca":null,"max_path_len":null}', '{}')
    assert (
        entity.certificate_policies
        == "[CertificatePolicy(cps=['http://cps.digicert.com/example-cps'], id='2.23.140.1.2.2', user_notice=Unset())]"
    )
    assert entity.crl_distribution_points == "['http://crl3.digicert.com/example.crl']"
    assert entity.extended_key_usage == "{}"
    assert entity.hashes == {
        "MD5": "956f4b8a30ec423d4bbec9ec60df71df",
        "SHA-1": "3ba7e9f806eb30d2f4e3f905e53f07e9acf08e1e",
        "SHA-256": "73b8ed5becf1ba6493d2e2215a42dfdc7877e91e311ff5e59fb43d094871e699",
    }
    assert entity.id == "x509-certificate--635308a7-3e2f-5ada-b384-f768c4493fe8"
    assert entity.is_self_signed is False
    assert (
        entity.issuer
        == "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"
    )
    assert entity.key_usage in (
        '{"certificate_sign":null,"content_commitment":null,"crl_sign":null,"data_encipherment":null,"decipher_only":null,"digital_signature":null,"encipher_only":null,"key_agreement":null,"key_encipherment":null,"value":null}',
        '{}',
    )
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.serial_number == "123456789"
    assert entity.signature_algorithm == "SHA256-RSA"
    assert entity.subject == "CN=one.one.one.one"
    assert entity.subject_public_key_algorithm == "ECDSA"
    assert entity.type == "x509-certificate"
    assert str(entity.validity_not_after) == "2026-01-02 00:00:00+00:00"
    assert str(entity.validity_not_before) == "2025-01-02 00:00:00+00:00"
    assert (
        entity.x_opencti_created_by_ref
        == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    )

    entity = stix_objects[15]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--c813aaca-81dc-5674-a9e0-33a9ca75db87"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "related-to"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.target_ref == "x509-certificate--635308a7-3e2f-5ada-b384-f768c4493fe8"
    assert entity.type == "relationship"

    entity = stix_objects[16]
    assert entity.abstract == "Service on port 443"
    assert entity.authors == ["Censys Enrichment Connector"]
    assert "HTTP/1.1 301 Moved Permanently" in entity.content
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "note--6c3109db-bdd5-5ff1-9c8d-29ad0e00bf34"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.object_refs == ["ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"]
    assert entity.type == "note"

    entity = stix_objects[17]
    assert entity.country == "Australia"
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "location--6004efb1-d850-551c-af0d-4717244377a8"
    assert entity.name == "Australia"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.type == "location"
    assert entity.x_opencti_location_type == "Country"

    entity = stix_objects[18]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--7b68d57e-cb08-5d7f-8aa9-83410e31a97f"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "located-at"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.target_ref == "location--6004efb1-d850-551c-af0d-4717244377a8"
    assert entity.type == "relationship"

    entity = stix_objects[19]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "identity--a7d63be9-7173-560e-9723-a5040d771c2c"
    assert entity.identity_class == "organization"
    assert entity.name == "CLOUDFLARENET"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.type == "identity"

    entity = stix_objects[20]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--072d0831-2ae0-569d-8b5c-6bd51aae1e16"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "related-to"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.target_ref == "identity--a7d63be9-7173-560e-9723-a5040d771c2c"
    assert entity.type == "relationship"

    entity = stix_objects[21]
    assert entity.id == "autonomous-system--0204c07d-e4dd-5f14-a3d5-c93cb1c5a9fc"
    assert entity.name == "CLOUDFLARENET"
    assert entity.number == 13335
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.type == "autonomous-system"
    assert (
        entity.x_opencti_created_by_ref
        == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    )
    assert entity.x_opencti_description == "CLOUDFLARENET"

    entity = stix_objects[22]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--3711db39-b33a-59bf-b0fd-e6949077d75d"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "belongs-to"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert (
        entity.target_ref == "autonomous-system--0204c07d-e4dd-5f14-a3d5-c93cb1c5a9fc"
    )
    assert entity.type == "relationship"

    entity = stix_objects[23]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--0e80e1b9-1b83-59fe-9caf-5c5725ecace3"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "related-to"
    assert (
        entity.source_ref == "autonomous-system--0204c07d-e4dd-5f14-a3d5-c93cb1c5a9fc"
    )
    assert entity.target_ref == "identity--a7d63be9-7173-560e-9723-a5040d771c2c"
    assert entity.type == "relationship"

    entity = stix_objects[24]
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "relationship--5386e469-d923-5136-ba8d-37f19ff162b4"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "related-to"
    assert (
        entity.source_ref == "autonomous-system--0204c07d-e4dd-5f14-a3d5-c93cb1c5a9fc"
    )
    assert entity.target_ref == "location--6004efb1-d850-551c-af0d-4717244377a8"
    assert entity.type == "relationship"

    # The enriched IP is re-emitted carrying the Censys pivot URL; OpenCTI merges
    # this with the existing observable (same deterministic STIX ID).
    entity = stix_objects[25]
    assert entity.type == "ipv4-addr"
    assert entity.id == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.value == "1.1.1.1"
    assert len(entity.x_opencti_external_references) == 1
    ext_ref = entity.x_opencti_external_references[0]
    assert ext_ref.source_name == "Censys"
    assert ext_ref.url == "https://platform.censys.io/hosts/1.1.1.1"


def test_converter_vulnerability_enrichment() -> None:
    """A service with a CVE produces a Vulnerability and a related-to relationship."""
    converter = Converter()
    host = Host(
        ip="203.0.113.1",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[
                    Vuln(
                        id="CVE-2021-44228",
                        name="Log4Shell",
                        metrics=Metrics(
                            cvss_v31=None,
                            cvss_v30=None,
                        ),
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.1"),
            data=host,
        )
    ]

    types = [o.type for o in stix_objects]
    assert "vulnerability" in types
    assert types.count("relationship") >= 1

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.name == "CVE-2021-44228"
    assert vuln_obj.description == "Log4Shell"

    # Relationship from IP to vulnerability
    rel = next(
        o
        for o in stix_objects
        if o.type == "relationship" and o.target_ref == vuln_obj.id
    )
    assert rel.relationship_type == "related-to"


def test_converter_malware_enrichment() -> None:
    """A service with a threat detection produces a Malware and a related-to relationship."""
    converter = Converter()
    host = Host(
        ip="203.0.113.2",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                threats=[
                    Threat(
                        name="CobaltStrike",
                        malware=ThreatMalware(primary_name="Cobalt Strike"),
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.2"),
            data=host,
        )
    ]

    types = [o.type for o in stix_objects]
    assert "malware" in types

    malware_obj = next(o for o in stix_objects if o.type == "malware")
    assert malware_obj.name == "Cobalt Strike"
    assert malware_obj.is_family is True

    rel = next(
        o
        for o in stix_objects
        if o.type == "relationship" and o.target_ref == malware_obj.id
    )
    assert rel.relationship_type == "related-to"


def test_converter_jarm_note() -> None:
    """A service with JARM data produces a fingerprints Note attached to the observable."""
    converter = Converter()
    host = Host(
        ip="203.0.113.3",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                jarm=JarmScan(
                    fingerprint="27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
                    cipher_and_version_fingerprint="27d40d40d29d40d1dc42d43d00041d",
                    tls_extensions_sha256="4689ee210389f4f6b4b5b1b93f92252d",
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.3"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    assert len(notes) == 1
    note = notes[0]
    assert note.abstract == "Service on port 443"
    assert "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d" in note.content


def test_converter_operating_system_enrichment() -> None:
    """A host with operating_system data produces a Software observable."""
    converter = Converter()
    host = Host(
        ip="203.0.113.4",
        operating_system=Attribute(
            product="Linux",
            vendor="kernel.org",
            cpe="cpe:2.3:o:linux:linux_kernel:5.15:*:*:*:*:*:*:*",
            version="5.15",
        ),
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.4"),
            data=host,
        )
    ]

    software_objs = [o for o in stix_objects if o.type == "software"]
    assert len(software_objs) == 1
    os_obj = software_objs[0]
    assert os_obj.name == "Linux"
    assert os_obj.vendor == "kernel.org"
    assert os_obj.version == "5.15"
    assert os_obj.cpe == "cpe:2.3:o:linux:linux_kernel:5.15:*:*:*:*:*:*:*"


def test_converter_software_version() -> None:
    """Service software with a version populates the Software version field."""
    converter = Converter()
    host = Host(
        ip="203.0.113.5",
        services=[
            Service(
                port=80,
                scan_time="2025-06-01T10:00:00Z",
                software=[
                    Attribute(
                        product="nginx",
                        vendor="nginx.org",
                        cpe="cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*",
                        version="1.25.0",
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.5"),
            data=host,
        )
    ]

    software_objs = [o for o in stix_objects if o.type == "software"]
    assert len(software_objs) == 1
    assert software_objs[0].version == "1.25.0"


def test_converter_external_reference_ipv6() -> None:
    """External reference is also added when enriching an IPv6 address."""
    converter = Converter()
    host = Host(ip="2606:4700:4700::1111")

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv6Address(value="2606:4700:4700::1111"),
            data=host,
        )
    ]

    ip_objs = [o for o in stix_objects if o.type == "ipv6-addr"]
    assert len(ip_objs) == 1
    ext_refs = ip_objs[0].x_opencti_external_references
    assert len(ext_refs) == 1
    assert ext_refs[0].source_name == "Censys"
    assert "platform.censys.io" in ext_refs[0].url
    assert "2606:4700:4700::1111" in ext_refs[0].url


def test_converter_service_fingerprints_note() -> None:
    """TLS handshake data, JA4TScan, and JARM are captured in a single fingerprints note."""
    converter = Converter()
    host = Host(
        ip="203.0.113.6",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                tls=TLS(
                    version_selected=VersionSelected.TLSV1_2,
                    cipher_selected="TLS_RSA_WITH_AES_256_GCM_SHA384",
                    ja3s="f75082535b4a79c07b31bdd0e2b7eb87",
                    ja4s="t120100_009d_bc98f8e001b5",
                ),
                ja4tscan=Ja4TScanScan(
                    fingerprint="64000_2-1-3-4-8_1460_0_1-2-4"
                ),
                jarm=JarmScan(
                    fingerprint="14d14d16d14d14d08c14d14d14d14dfd9c9d14e4f4f67f94f0359f8b28f532",
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.6"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    assert len(notes) == 1
    note = notes[0]
    assert note.abstract == "Service on port 443"
    assert "**Version:**" in note.content
    assert "**Cipher:**" in note.content
    assert "**JA3S:**" in note.content
    assert "**JA4S:**" in note.content
    assert "#### JA4TScan" in note.content
    assert "#### JARM" in note.content


def test_converter_reverse_dns_hostnames() -> None:
    """Reverse DNS PTR records produce Hostname observables, deduplicating against dns.names."""
    converter = Converter()
    host = Host(
        ip="203.0.113.7",
        dns=HostDNS(
            names=["forward.example.com"],
            reverse_dns=HostDNSReverseResolution(
                # forward.example.com appears in both; should only produce one Hostname
                names=["ptr.example.com", "forward.example.com"],
            ),
        ),
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.7"),
            data=host,
        )
    ]

    hostnames = [o for o in stix_objects if o.type == "hostname"]
    values = {h.value for h in hostnames}
    assert values == {"forward.example.com", "ptr.example.com"}


def test_converter_labels() -> None:
    """Censys host labels are applied as OpenCTI labels on the IP observable."""
    converter = Converter()
    host = Host(
        ip="203.0.113.8",
        labels=[Label(value="cloud-provider"), Label(value="cdn")],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.8"),
            data=host,
        )
    ]

    ip_objs = [o for o in stix_objects if o.type == "ipv4-addr"]
    assert len(ip_objs) == 1
    assert set(ip_objs[0].x_opencti_labels) == {"cloud-provider", "cdn"}


def test_converter_cobalt_strike_note() -> None:
    """A service with Cobalt Strike beacon data produces a dedicated configuration note."""
    converter = Converter()
    host = Host(
        ip="185.92.190.213",
        services=[
            Service(
                port=5896,
                scan_time="2025-06-01T10:00:00Z",
                endpoints=[
                    EndpointScanState(
                        port=5896,
                        scan_time="2025-06-01T10:00:00Z",
                        cobalt_strike=CobaltStrike(
                            x64=CobaltStrikeConfig(
                                user_agent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)",
                                sleep_time=60000,
                                jitter=0,
                                dns=True,
                                ssl=False,
                                cookie_beacon=1,
                                killdate=0,
                                watermark=987654321,
                                http_get=CobaltStrikeHTTPConfig(verb="GET", uri="/j.ad"),
                                http_post=CobaltStrikeHTTPConfig(verb="POST", uri="/submit.php"),
                                post_ex=CobaltStrikePostEx(
                                    x64="%windir%\\sysnative\\rundll32.exe",
                                    x86="%windir%\\syswow64\\rundll32.exe",
                                ),
                                public_key="30819f300d06092a864886f70d010101050003818d",
                            ),
                            x86=CobaltStrikeConfig(
                                user_agent="Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.1)",
                                sleep_time=60000,
                                watermark=987654321,
                            ),
                        ),
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="185.92.190.213"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    cs_notes = [n for n in notes if "Cobalt Strike" in n.abstract]
    assert len(cs_notes) == 1
    note = cs_notes[0]
    assert note.abstract == "Cobalt Strike beacon configuration on port 5896"
    # x64 section
    assert "### Arch: x64" in note.content
    assert "Mozilla/4.0" in note.content
    assert "**Sleep Time:** 60000 ms" in note.content
    assert "**Watermark:** 987654321" in note.content
    assert "**GET** `GET /j.ad`" in note.content
    assert "**POST** `POST /submit.php`" in note.content
    assert "30819f300d06092a864886f70d010101050003818d" in note.content
    # x86 section
    assert "### Arch: x86" in note.content
    assert "Mozilla/5.0" in note.content
    # Cobalt Strike notes always carry malware labels and the port
    assert set(note.labels) == {"cobalt-strike", "malware", "port:5896"}


def test_converter_dcerpc_note() -> None:
    """DCERPC endpoint data produces a note with executable/protocol rows and rpc labels."""
    converter = Converter()
    host = Host(
        ip="203.0.113.20",
        services=[
            Service(
                port=135,
                scan_time="2025-06-01T10:00:00Z",
                dcerpc=Dcerpc(
                    could_query_epm=True,
                    endpoints=[
                        DcerpcEndpoint(
                            executable="taskcomp.dll",
                            protocol="[MS-TSCH]: Task Scheduler Service Remoting Protocol",
                        ),
                        DcerpcEndpoint(
                            executable="samsrv.dll",
                            protocol="[MS-SAMR]: Security Account Manager (SAM) Remote Protocol",
                        ),
                    ],
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.20"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    dcerpc_notes = [n for n in notes if "DCERPC" in n.abstract]
    assert len(dcerpc_notes) == 1
    note = dcerpc_notes[0]
    assert note.abstract == "Port 135 — DCERPC"
    assert "**EPM Queryable:** True" in note.content
    assert "taskcomp.dll" in note.content
    assert "[MS-TSCH]" in note.content
    assert "samsrv.dll" in note.content
    assert "[MS-SAMR]" in note.content
    assert set(note.labels) == {"dcerpc", "rpc", "port:135"}


def test_converter_ssh_note() -> None:
    """SSH service produces a note with banner, HASSH, and host key fingerprint."""
    converter = Converter()
    host = Host(
        ip="203.0.113.21",
        services=[
            Service(
                port=22,
                scan_time="2025-06-01T10:00:00Z",
                ssh=SSH(
                    endpoint_id=SSHEndpointID(raw="SSH-2.0-OpenSSH_8.9"),
                    hassh_fingerprint="ec7378c1a92f5a8dde7e8b7a1dfc6d09",
                    server_host_key=SSHServerHostKey(
                        fingerprint_sha256="SHA256:abc123def456"
                    ),
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.21"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    ssh_notes = [n for n in notes if "SSH" in n.abstract]
    assert len(ssh_notes) == 1
    note = ssh_notes[0]
    assert note.abstract == "Port 22 — SSH"
    assert "SSH-2.0-OpenSSH_8.9" in note.content
    assert "ec7378c1a92f5a8dde7e8b7a1dfc6d09" in note.content
    assert "SHA256:abc123def456" in note.content
    assert note.labels == ["port:22", "ssh"]


def test_converter_smb_note() -> None:
    """SMB service produces a note with OS, workgroup, and dialect information."""
    converter = Converter()
    host = Host(
        ip="203.0.113.22",
        services=[
            Service(
                port=445,
                scan_time="2025-06-01T10:00:00Z",
                smb=Smb(
                    native_os="Windows Server 2019",
                    group_name="CORP",
                    smbv1_support=False,
                    negotiation_log=SmbNegotiationLog(
                        dialect_revision=0x0311,
                        server_guid="aabbccdd-eeff-0011-2233-445566778899",
                    ),
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.22"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    smb_notes = [n for n in notes if "SMB" in n.abstract]
    assert len(smb_notes) == 1
    note = smb_notes[0]
    assert note.abstract == "Port 445 — SMB"
    assert "Windows Server 2019" in note.content
    assert "CORP" in note.content
    assert "**SMBv1 Support:** False" in note.content
    assert "**Dialect:** 785" in note.content
    assert note.labels == ["port:445", "smb"]


def test_converter_winrm_note() -> None:
    """WinRM service surfaces NTLM domain, forest, and OS version from NTLM challenge."""
    converter = Converter()
    host = Host(
        ip="203.0.113.23",
        services=[
            Service(
                port=5985,
                scan_time="2025-06-01T10:00:00Z",
                winrm=Winrm(
                    ntlm_info=NtlmInfo(
                        dns_domain_name="corp.example.com",
                        dns_tree_name="example.com",
                        netbios_domain_name="CORP",
                        netbios_computer_name="SRV-DC01",
                        os_version="10.0.17763",
                    )
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.23"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    winrm_notes = [n for n in notes if "WINRM" in n.abstract]
    assert len(winrm_notes) == 1
    note = winrm_notes[0]
    assert note.abstract == "Port 5985 — WINRM"
    assert "corp.example.com" in note.content
    assert "example.com" in note.content
    assert "SRV-DC01" in note.content
    assert "10.0.17763" in note.content
    assert set(note.labels) == {"winrm", "windows", "port:5985"}


def test_converter_service_risks_note() -> None:
    """Services with exposures/misconfigs/compromises produce a risks note with labels."""
    converter = Converter()
    host = Host(
        ip="203.0.113.24",
        services=[
            Service(
                port=8080,
                scan_time="2025-06-01T10:00:00Z",
                exposures=[
                    Risk(name="Open Proxy", severity=Severity.HIGH),
                ],
                misconfigs=[
                    Risk(name="Default Credentials", severity=Severity.CRITICAL),
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.24"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    risk_notes = [n for n in notes if n.abstract == "Service on port 8080"]
    assert len(risk_notes) == 1
    note = risk_notes[0]
    assert note.abstract == "Service on port 8080"
    assert "#### Exposures" in note.content
    assert "Open Proxy" in note.content
    assert "[HIGH]" in note.content
    assert "#### Misconfigurations" in note.content
    assert "Default Credentials" in note.content
    assert "[CRITICAL]" in note.content
    assert set(note.labels) == {"exposure", "misconfiguration", "port:8080"}


# ---------------------------------------------------------------------------
# New tests for SDK 0.14.x features
# ---------------------------------------------------------------------------


def test_converter_vulnerability_kev_epss() -> None:
    """Vulnerabilities with KEV/EPSS data populate is_cisa_kev, epss_score, epss_percentile."""
    from censys_platform import Epss

    converter = Converter()
    host = Host(
        ip="203.0.113.30",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[
                    Vuln(
                        id="CVE-2021-44228",
                        name="Log4Shell",
                        kev=[Kev(date_added="2021-12-10", source=KEVSource.CISA)],
                        metrics=Metrics(
                            cvss_v31=None,
                            cvss_v30=None,
                            epss=Epss(score=0.97, percentile=0.995),
                        ),
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.30"),
            data=host,
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.name == "CVE-2021-44228"
    assert vuln_obj.x_opencti_cisa_kev is True
    assert vuln_obj.x_opencti_epss_score == 0.97
    assert vuln_obj.x_opencti_epss_percentile == 0.995


def test_converter_malware_malpedia_external_reference() -> None:
    """Threats with Malpedia IDs produce Malware with an external reference URL."""
    converter = Converter()
    host = Host(
        ip="203.0.113.31",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                threats=[
                    Threat(
                        name="CobaltStrike",
                        malware=ThreatMalware(
                            primary_name="Cobalt Strike",
                            malpedia_id="win.cobalt_strike",
                            all_names=["Cobalt Strike", "CobaltStrike", "CS Beacon"],
                        ),
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.31"),
            data=host,
        )
    ]

    malware_obj = next(o for o in stix_objects if o.type == "malware")
    assert malware_obj.name == "Cobalt Strike"
    assert malware_obj.is_family is True

    ext_refs = malware_obj.external_references
    assert ext_refs, "Expected external_references on malware"
    malpedia_ref = next((r for r in ext_refs if r.source_name == "Malpedia"), None)
    assert malpedia_ref is not None
    assert "win.cobalt_strike" in malpedia_ref.url
    assert malpedia_ref.external_id == "win.cobalt_strike"


def test_converter_service_risks_note_with_compromises() -> None:
    """Services with compromises produce a risks note that includes the compromise section and label."""
    converter = Converter()
    host = Host(
        ip="203.0.113.32",
        services=[
            Service(
                port=8080,
                scan_time="2025-06-01T10:00:00Z",
                compromises=[
                    Risk(name="Compromised Host", severity=Severity.CRITICAL),
                ],
                exposures=[
                    Risk(name="Open Proxy", severity=Severity.HIGH),
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.32"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    risk_note = next(n for n in notes if "port:8080" in n.labels)
    assert "#### Compromises" in risk_note.content
    assert "Compromised Host" in risk_note.content
    assert "[CRITICAL]" in risk_note.content
    assert "#### Exposures" in risk_note.content
    assert "compromise" in risk_note.labels
    assert "exposure" in risk_note.labels
    assert "port:8080" in risk_note.labels


def test_converter_smtp_note() -> None:
    """A service with SMTP data produces a note with EHLO response."""
    from censys_platform import SMTP

    converter = Converter()
    host = Host(
        ip="203.0.113.33",
        services=[
            Service(
                port=25,
                scan_time="2025-06-01T10:00:00Z",
                smtp=SMTP(
                    ehlo="mail.example.com\n250-SIZE 52428800\n250 STARTTLS",
                    start_tls="220 Ready to start TLS",
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.33"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    assert len(notes) == 1
    note = notes[0]
    assert note.abstract == "Port 25 — SMTP"
    assert "mail.example.com" in note.content
    assert "STARTTLS" in note.content
    assert note.labels == ["port:25", "smtp"]


def test_converter_ftp_note() -> None:
    """A service with FTP data produces a note with status and TLS support."""
    from censys_platform import Ftp

    converter = Converter()
    host = Host(
        ip="203.0.113.34",
        services=[
            Service(
                port=21,
                scan_time="2025-06-01T10:00:00Z",
                ftp=Ftp(
                    status_code=220,
                    status_meaning="Service ready",
                    implicit_tls=False,
                    auth_tls_response="234 AUTH TLS successful",
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.34"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    assert len(notes) == 1
    note = notes[0]
    assert note.abstract == "Port 21 — FTP"
    assert "220" in note.content
    assert "Service ready" in note.content
    assert "234 AUTH TLS successful" in note.content
    assert note.labels == ["port:21", "ftp"]


def test_converter_telnet_note() -> None:
    """An exposed Telnet service produces a note flagging its plaintext nature."""
    from censys_platform import Telnet

    converter = Converter()
    host = Host(
        ip="203.0.113.35",
        services=[
            Service(
                port=23,
                scan_time="2025-06-01T10:00:00Z",
                telnet=Telnet(
                    will={"ECHO": "echo", "SGA": "suppress-go-ahead"},
                    do={"NAWS": "window-size"},
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.35"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    assert len(notes) == 1
    note = notes[0]
    assert note.abstract == "Port 23 — TELNET"
    assert "plaintext" in note.content
    assert note.labels == ["port:23", "telnet"]


def test_converter_redis_note() -> None:
    """A service with Redis data produces a note with version, mode, and auth status."""
    from censys_platform import Redis

    converter = Converter()
    host = Host(
        ip="203.0.113.36",
        services=[
            Service(
                port=6379,
                scan_time="2025-06-01T10:00:00Z",
                redis=Redis(
                    major=7,
                    minor=0,
                    patch_level=5,
                    mode="standalone",
                    os="Linux 5.15.0 x86_64",
                    ping_response="PONG",
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.36"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    assert len(notes) == 1
    note = notes[0]
    assert note.abstract == "Port 6379 — REDIS"
    assert "7.0.5" in note.content
    assert "standalone" in note.content
    assert "Disabled" in note.content  # unauthenticated
    assert note.labels == ["port:6379", "redis"]


def test_converter_mongodb_note() -> None:
    """A service with MongoDB data produces a note with version and server role."""
    from censys_platform import Mongodb, MongodbBuildInfo, MongodbIsMaster

    converter = Converter()
    host = Host(
        ip="203.0.113.37",
        services=[
            Service(
                port=27017,
                scan_time="2025-06-01T10:00:00Z",
                mongodb=Mongodb(
                    build_info=MongodbBuildInfo(version="6.0.5"),
                    is_master=MongodbIsMaster(
                        is_master=True,
                        read_only=False,
                        max_wire_version=17,
                    ),
                ),
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.37"),
            data=host,
        )
    ]

    notes = [o for o in stix_objects if o.type == "note"]
    assert len(notes) == 1
    note = notes[0]
    assert note.abstract == "Port 27017 — MONGODB"
    assert "6.0.5" in note.content
    assert "True" in note.content  # is_master
    assert note.labels == ["port:27017", "mongodb"]


def test_converter_cvss4_invalid_vector_is_silently_dropped() -> None:
    """A malformed CVSS 4.0 vector string is dropped rather than forwarded to OpenCTI."""
    from censys_platform import CVSSv4, Metrics

    converter = Converter()
    host = Host(
        ip="203.0.113.40",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[
                    Vuln(
                        id="CVE-2024-99999",
                        metrics=Metrics(
                            cvss_v40=CVSSv4(
                                score=9.1,
                                # Intentionally malformed — missing the CVSS:4.0/ prefix
                                vector="AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                            ),
                        ),
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.40"),
            data=host,
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.name == "CVE-2024-99999"
    # Score is always forwarded regardless of the vector; vector string is always dropped.
    assert getattr(vuln_obj, "x_opencti_cvss_v4_base_score", None) == 9.1
    assert not getattr(vuln_obj, "x_opencti_cvss_v4_vector_string", None)


def test_converter_cvss4_score_is_preserved() -> None:
    """CVSS 4.0 score passes through; vector string is never forwarded to OpenCTI
    because Censys can include supplemental metrics that OpenCTI's validator rejects.
    """
    from censys_platform import CVSSv4, Metrics

    converter = Converter()
    valid_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    host = Host(
        ip="203.0.113.41",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[
                    Vuln(
                        id="CVE-2024-99998",
                        metrics=Metrics(cvss_v40=CVSSv4(score=9.3, vector=valid_vector)),
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.41"),
            data=host,
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.x_opencti_cvss_v4_base_score == 9.3
    # Vector string is always suppressed to avoid OpenCTI validation failures.
    assert not getattr(vuln_obj, "x_opencti_cvss_v4_vector_string", None)


def test_converter_vulnerability_description_from_cve_descriptions() -> None:
    """An explicit nvd_data_map entry overrides the vuln.name fallback."""
    converter = Converter()
    host = Host(
        ip="203.0.113.42",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[Vuln(id="CVE-2021-44228", name="Log4Shell")],
            )
        ],
    )

    nvd_text = (
        "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in "
        "configuration, log messages, and parameters do not protect against "
        "attacker controlled LDAP and other JNDI related endpoints."
    )
    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.42"),
            data=host,
            nvd_data_map={"CVE-2021-44228": NVDData(description=nvd_text)},
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.name == "CVE-2021-44228"
    # NVD text should win over the shorter vuln.name fallback
    assert vuln_obj.description == nvd_text


def test_converter_vulnerability_description_fallback_to_vuln_name() -> None:
    """When no nvd_data_map entry is supplied vuln.name is used as the fallback."""
    converter = Converter()
    host = Host(
        ip="203.0.113.43",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[Vuln(id="CVE-2021-44228", name="Log4Shell")],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.43"),
            data=host,
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.name == "CVE-2021-44228"
    assert vuln_obj.description == "Log4Shell"


def test_converter_vulnerability_cwe_labels() -> None:
    """CWE entries on a Censys vuln are propagated as labels on the Vulnerability."""
    converter = Converter()
    host = Host(
        ip="203.0.113.50",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[
                    Vuln(
                        id="CVE-2021-44228",
                        cwes=[Cwe(entry="CWE-502"), Cwe(entry="CWE-20")],
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.50"),
            data=host,
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.name == "CVE-2021-44228"
    labels = getattr(vuln_obj, "labels", None) or getattr(vuln_obj, "x_opencti_labels", None)
    assert labels is not None
    assert "CWE-502" in labels
    assert "CWE-20" in labels


def test_converter_vulnerability_cvss3_components() -> None:
    """CVSS v3 component fields are populated from Censys CVSSComponents data."""
    from censys_platform import Cvss
    from censys_platform.models.cvss_components import (
        AttackComplexity,
        AttackVector,
        Availability,
        Confidentiality,
        Integrity,
        PrivilegesRequired,
        Scope,
        UserInteraction,
        CVSSComponents,
    )

    converter = Converter()
    host = Host(
        ip="203.0.113.51",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[
                    Vuln(
                        id="CVE-2021-44228",
                        metrics=Metrics(
                            cvss_v31=Cvss(
                                score=10.0,
                                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                components=CVSSComponents(
                                    attack_vector=AttackVector.NETWORK,
                                    attack_complexity=AttackComplexity.LOW,
                                    privileges_required=PrivilegesRequired.NONE,
                                    user_interaction=UserInteraction.NONE,
                                    scope=Scope.CHANGED,
                                    confidentiality=Confidentiality.HIGH,
                                    integrity=Integrity.HIGH,
                                    availability=Availability.HIGH,
                                ),
                            )
                        ),
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.51"),
            data=host,
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.x_opencti_cvss_attack_vector == "NETWORK"
    assert vuln_obj.x_opencti_cvss_attack_complexity == "LOW"
    assert vuln_obj.x_opencti_cvss_privileges_required == "NONE"
    assert vuln_obj.x_opencti_cvss_user_interaction == "NONE"
    assert vuln_obj.x_opencti_cvss_scope == "CHANGED"
    assert vuln_obj.x_opencti_cvss_confidentiality_impact == "HIGH"
    assert vuln_obj.x_opencti_cvss_integrity_impact == "HIGH"
    assert vuln_obj.x_opencti_cvss_availability_impact == "HIGH"


def test_converter_vulnerability_cvss3_severity_from_nvd() -> None:
    """NVD-provided v3 base severity takes priority over the Censys severity field."""
    from censys_platform.models.vuln import VulnSeverity

    converter = Converter()
    host = Host(
        ip="203.0.113.52",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[
                    Vuln(
                        id="CVE-2021-44228",
                        severity=VulnSeverity.MEDIUM,  # Censys says MEDIUM
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.52"),
            data=host,
            # NVD says CRITICAL — should win
            nvd_data_map={"CVE-2021-44228": NVDData(cvss_v3_base_severity="CRITICAL")},
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.x_opencti_cvss_base_severity.value == "CRITICAL"


def test_converter_vulnerability_cvss3_severity_fallback_to_censys() -> None:
    """When NVD has no severity, Censys vuln.severity is used as fallback."""
    from censys_platform.models.vuln import VulnSeverity

    converter = Converter()
    host = Host(
        ip="203.0.113.53",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[
                    Vuln(
                        id="CVE-2021-44228",
                        severity=VulnSeverity.HIGH,
                    )
                ],
            )
        ],
    )

    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.53"),
            data=host,
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    assert vuln_obj.x_opencti_cvss_base_severity.value == "HIGH"


def test_converter_vulnerability_nvd_cvss_v2() -> None:
    """CVSS v2 fields from NVDData are propagated onto the Vulnerability object."""
    converter = Converter()
    host = Host(
        ip="203.0.113.54",
        services=[
            Service(
                port=80,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[Vuln(id="CVE-2008-4250")],
            )
        ],
    )

    nvd = NVDData(
        cvss_v2_base_score=10.0,
        cvss_v2_vector_string="AV:N/AC:L/Au:N/C:C/I:C/A:C",
        cvss_v2_access_vector="NETWORK",
        cvss_v2_access_complexity="LOW",
        cvss_v2_authentication="NONE",
        cvss_v2_confidentiality_impact="COMPLETE",
        cvss_v2_integrity_impact="COMPLETE",
        cvss_v2_availability_impact="COMPLETE",
    )
    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.54"),
            data=host,
            nvd_data_map={"CVE-2008-4250": nvd},
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    # Note: cvss_v2_base_score is not serialised as a STIX extension field
    assert vuln_obj.x_opencti_cvss_v2_vector_string == "AV:N/AC:L/Au:N/C:C/I:C/A:C"
    assert vuln_obj.x_opencti_cvss_v2_access_vector == "NETWORK"
    assert vuln_obj.x_opencti_cvss_v2_access_complexity == "LOW"
    assert vuln_obj.x_opencti_cvss_v2_authentication == "NONE"
    assert vuln_obj.x_opencti_cvss_v2_confidentiality_impact == "COMPLETE"
    assert vuln_obj.x_opencti_cvss_v2_integrity_impact == "COMPLETE"
    assert vuln_obj.x_opencti_cvss_v2_availability_impact == "COMPLETE"


def test_converter_vulnerability_nvd_external_references() -> None:
    """NVD external references are surfaced as ExternalReference objects on the Vulnerability."""
    converter = Converter()
    host = Host(
        ip="203.0.113.55",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[Vuln(id="CVE-2021-44228")],
            )
        ],
    )

    nvd = NVDData(
        references=[
            NVDReference(
                url="https://logging.apache.org/log4j/2.x/security.html",
                source_name="Vendor Advisory",
            ),
            NVDReference(
                url="https://github.com/apache/logging-log4j2/releases/tag/rel%2F2.15.0",
                source_name="Patch, Release Notes",
            ),
        ]
    )
    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.55"),
            data=host,
            nvd_data_map={"CVE-2021-44228": nvd},
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    ext_refs = vuln_obj.external_references
    assert ext_refs is not None and len(ext_refs) == 2
    urls = {r.url for r in ext_refs}
    assert "https://logging.apache.org/log4j/2.x/security.html" in urls
    assert "https://github.com/apache/logging-log4j2/releases/tag/rel%2F2.15.0" in urls
    source_names = {r.source_name for r in ext_refs}
    assert "Vendor Advisory" in source_names
    assert "Patch, Release Notes" in source_names


def test_converter_vulnerability_affected_software_yields_software_and_has_rel() -> None:
    """Software observables are created for each NVD affected_software entry and
    linked to the Vulnerability via a HAS relationship."""
    converter = Converter()
    host = Host(
        ip="203.0.113.60",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[Vuln(id="CVE-2021-44228")],
            )
        ],
    )
    nvd = NVDData(
        affected_software=[
            NVDAffectedSoftware(
                vendor="Apache",
                product="Log4J",
                cpe="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                version_info=">= 2.0, < 2.15.0",
            )
        ]
    )
    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.60"),
            data=host,
            nvd_data_map={"CVE-2021-44228": nvd},
        )
    ]

    vuln_obj = next(o for o in stix_objects if o.type == "vulnerability")
    sw_objects = [o for o in stix_objects if o.type == "software"]
    assert len(sw_objects) == 1
    sw = sw_objects[0]
    assert sw.name == "Log4J"
    assert sw.vendor == "Apache"
    assert sw.version == ">= 2.0, < 2.15.0"

    has_rels = [
        o for o in stix_objects
        if o.type == "relationship" and o.relationship_type == "related-to"
        and o.source_ref == sw.id
    ]
    assert len(has_rels) == 1
    assert has_rels[0].source_ref == sw.id
    assert has_rels[0].target_ref == vuln_obj.id


def test_converter_vulnerability_no_software_when_affected_software_empty() -> None:
    """No Software objects are yielded when NVDData.affected_software is empty."""
    converter = Converter()
    host = Host(
        ip="203.0.113.61",
        services=[
            Service(
                port=443,
                scan_time="2025-06-01T10:00:00Z",
                vulns=[Vuln(id="CVE-2021-44228")],
            )
        ],
    )
    nvd = NVDData()  # affected_software defaults to []
    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="203.0.113.61"),
            data=host,
            nvd_data_map={"CVE-2021-44228": nvd},
        )
    ]
    assert not any(o.type == "software" for o in stix_objects)


def test_fetch_nvd_data_parses_cpe_configurations() -> None:
    """fetch_nvd_data populates affected_software from CPE configurations."""
    from unittest.mock import MagicMock, patch

    from censys_enrichment.client import Client

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "descriptions": [{"lang": "en", "value": "A critical RCE."}],
                    "metrics": {},
                    "references": [],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "2.0.0",
                                            "versionEndExcluding": "2.15.0",
                                        },
                                        {
                                            "vulnerable": False,
                                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:oracle:weblogic_server:12.2.1.4.0:*:*:*:*:*:*:*",
                                        },
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }

    client = Client(organisation_id="org", token="tok")
    with patch("requests.get", return_value=mock_response):
        result = client.fetch_nvd_data("CVE-2021-44228")

    assert result is not None
    assert len(result.affected_software) == 2

    sw_by_product = {sw.product: sw for sw in result.affected_software}

    log4j = sw_by_product["Log4J"]
    assert log4j.vendor == "Apache"
    assert log4j.cpe == "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
    assert log4j.version_info == ">= 2.0.0, < 2.15.0"

    weblogic = sw_by_product["Weblogic Server"]
    assert weblogic.vendor == "Oracle"
    assert weblogic.version_info == "12.2.1.4.0"

    # The non-vulnerable OS entry must be excluded
    assert not any(sw.vendor == "Linux" for sw in result.affected_software)


def test_converter_whois_abuse_email_invalid_values_are_dropped() -> None:
    """Malformed WHOIS abuse-contact values must never produce an EmailAddress
    observable — OpenCTI enforces RFC 5321 and returns FUNCTIONAL_ERROR for
    values like 'N/A', 'abuse@' (no domain), or plain handles."""
    from censys_platform.models.contact import Contact
    from censys_platform.models.organization import Organization as CensysOrg
    from censys_platform.models.whois import Whois

    converter = Converter()
    host = Host(
        ip="198.51.100.1",
        whois=Whois(
            organization=CensysOrg(
                abuse_contacts=[
                    Contact(email="abuse@example.com"),   # valid — should be kept
                    Contact(email="N/A"),                 # no @
                    Contact(email="abuse@"),              # no domain
                    Contact(email="postmaster"),          # no @
                    Contact(email=""),                    # empty
                    Contact(email=None),                  # None
                    Contact(email="noc@provider.net"),   # valid — should be kept
                ]
            )
        ),
    )
    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="198.51.100.1"),
            data=host,
        )
    ]

    email_values = {o.value for o in stix_objects if o.type == "email-addr"}
    assert "abuse@example.com" in email_values
    assert "noc@provider.net" in email_values
    # Malformed entries must be absent
    assert not any(v in email_values for v in ("N/A", "abuse@", "postmaster", ""))


def test_converter_cert_san_ip_addresses_not_emitted_as_hostnames() -> None:
    """Certificate SANs that are IP addresses (v4 or v6) must never produce
    Hostname observables.  OpenCTI enforces a strict hostname format and rejects
    IP strings with FUNCTIONAL_ERROR, which then cascades into
    MISSING_REFERENCE_ERROR for the cert→hostname relationship."""
    from .factories import CertificateFactory

    cert = CertificateFactory(
        names=[
            "example.com",           # valid hostname — should produce Hostname
            "*.example.com",         # wildcard — must be skipped
            "192.0.2.1",             # IPv4 SAN — must NOT produce Hostname
            "2400:c620:2f:6e::a",    # IPv6 SAN — must NOT produce Hostname
            "sub.example.org",       # valid hostname — should produce Hostname
        ]
    )
    converter = Converter()
    stix_objects = [
        obj.to_stix2_object()
        for obj in converter.generate_octi_objects_from_certs(certs=[cert])
    ]

    hostname_values = {o.value for o in stix_objects if o.type == "hostname"}
    assert "example.com" in hostname_values
    assert "sub.example.org" in hostname_values
    # IP addresses and wildcards must be absent
    assert "192.0.2.1" not in hostname_values
    assert "2400:c620:2f:6e::a" not in hostname_values
    assert not any(v.startswith("*") for v in hostname_values)
