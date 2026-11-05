"""Tests for the WHOIS-to-STIX converter."""

from pycti import STIX_EXT_OCTI_SCO
from whoisfreaks_client.models import WhoisRecord


def _entity(value="example.com"):
    return {
        "id": "domain-name--0b8e4f8a-0000-5000-8000-000000000001",
        "type": "domain-name",
        "value": value,
    }


def _by_type(objects):
    grouped: dict[str, list] = {}
    for obj in objects:
        grouped.setdefault(obj["type"], []).append(obj)
    return grouped


def test_build_full_record_creates_registrar_nameservers_emails_and_note(
    converter, full_record
):
    entity = _entity()
    objects = converter.build(full_record, entity)
    grouped = _by_type(objects)

    # Author + registrar + registrant organization are all identities.
    assert grouped["identity"]
    # Two name servers become domain-name observables.
    assert len(grouped["domain-name"]) == 2
    ns_values = {obj["value"] for obj in grouped["domain-name"]}
    assert ns_values == {"a.iana-servers.net", "b.iana-servers.net"}
    # Distinct contact e-mails become email-addr observables.
    emails = {obj["value"] for obj in grouped["email-addr"]}
    assert "registrant@example.com" in emails
    assert "admin@example.com" in emails
    assert "abuse@iana.org" in emails
    # One note with the WHOIS report.
    assert len(grouped["note"]) == 1
    assert "WHOIS Summary" in grouped["note"][0]["content"]
    # Relationships link the observable to the new entities.
    assert grouped["relationship"]
    assert all(
        rel["source_ref"] == entity["id"]
        or rel["target_ref"] == entity["id"]
        or rel["relationship_type"] == "related-to"
        for rel in grouped["relationship"]
    )


def test_build_sets_dnssec_label_and_external_reference(converter, full_record):
    entity = _entity()
    converter.build(full_record, entity)

    ext = entity["extensions"][STIX_EXT_OCTI_SCO]
    assert "dnssec" in ext["labels"]
    refs = ext["external_references"]
    assert refs and refs[0]["source_name"] == "WhoisFreaks"


def test_redacted_contacts_are_skipped(converter, redacted_record):
    objects = converter.build(redacted_record, _entity("privacy-domain.com"))
    grouped = _by_type(objects)

    # No contact e-mails survive redaction.
    assert "email-addr" not in grouped
    # Registrant organization "REDACTED FOR PRIVACY" is not created, but the
    # registrar (GoDaddy) still is.
    identity_names = {obj["name"] for obj in grouped["identity"]}
    assert "GoDaddy.com, LLC" in identity_names
    assert "REDACTED FOR PRIVACY" not in identity_names


def test_unregistered_domain_gets_an_unregistered_label(converter, unregistered_record):
    entity = _entity("this-domain-is-free-9z.com")
    converter.build(unregistered_record, entity)

    ext = entity["extensions"][STIX_EXT_OCTI_SCO]
    assert "unregistered" in ext["labels"]


def test_privacy_and_gdpr_emails_are_not_mistaken_for_redaction(converter):
    """`privacy@`/`gdpr@` are real addresses, not placeholders, and must be kept."""
    record = WhoisRecord.from_response(
        {
            "domain_name": "example.com",
            "domain_registered": "yes",
            "registrant_contact": {"email_address": "privacy@example.com"},
            "administrative_contact": {"email_address": "gdpr@example.com"},
        }
    )

    objects = converter.build(record, _entity())
    emails = {o["value"] for o in _by_type(objects).get("email-addr", [])}

    assert "privacy@example.com" in emails
    assert "gdpr@example.com" in emails


def test_relationships_can_be_disabled(converter, full_record):
    objects = converter.build(full_record, _entity(), create_relationships=False)
    grouped = _by_type(objects)

    assert "relationship" not in grouped
    # Entities (registrar, name servers, emails, note) are still created.
    assert grouped["domain-name"]
