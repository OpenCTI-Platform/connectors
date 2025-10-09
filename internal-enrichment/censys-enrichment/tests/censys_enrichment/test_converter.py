import stix2
from censys_enrichment.converter import Converter
from censys_platform import Host


def test_converter_ipv4(host_ipv4: Host) -> None:
    converter = Converter()

    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in converter.generate_octi_objects(
            stix_entity=stix2.IPv4Address(value="1.1.1.1"),
            data=host_ipv4,
        )
    ]

    assert len(stix_objects) == 25

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
    assert entity.id == "relationship--7321d77c-5f03-5d5e-a941-162364c5baca"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "related-to"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.target_ref == "hostname--2aa1a527-f7f9-59c6-aa42-716270bccb27"
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
    assert entity.id == "relationship--ffe16cae-f7d4-5a35-96bb-cb5bcb116f51"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "related-to"
    assert entity.source_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
    assert entity.target_ref == "hostname--21f6b21c-7cae-55af-b29b-54628a2c56f4"
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
    assert entity.basic_constraints == '{"is_ca":null,"max_path_len":null}'
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
    assert (
        entity.key_usage
        == '{"certificate_sign":null,"content_commitment":null,"crl_sign":null,"data_encipherment":null,"decipher_only":null,"digital_signature":null,"encipher_only":null,"key_agreement":null,"key_encipherment":null,"value":null}'
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
    assert entity.abstract == "Service banner on port 443"
    assert entity.authors == ["Censys Enrichment Connector"]
    assert entity.content == "HTTP/1.1 301 Moved Permanently"
    assert entity.created_by_ref == "identity--6f9f67f6-7eb2-5397-a02f-d8130aadb954"
    assert entity.id == "note--ec194bf2-4ee0-5338-857f-4c3f727b8ebf"
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
    assert entity.id == "relationship--fb347070-7d12-5bbb-bf74-59ede364e651"
    assert entity.object_marking_refs == [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
    assert entity.relationship_type == "related-to"
    assert (
        entity.source_ref == "autonomous-system--0204c07d-e4dd-5f14-a3d5-c93cb1c5a9fc"
    )
    assert entity.target_ref == "ipv4-addr--cbd67181-b9f8-595b-8bc3-3971e34fa1cc"
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
