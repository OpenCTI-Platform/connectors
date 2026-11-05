"""Tests for the WHOIS markdown note generator."""

from whoisfreaks_client.models import WhoisRecord


def test_summary_table_lists_the_core_whois_fields(md_gen, full_record):
    note = md_gen.generate(full_record)

    assert "## WHOIS Summary" in note
    assert "example.com" in note
    assert "1995-08-14" in note  # creation date
    assert "2025-08-13" in note  # expiry date
    assert "RESERVED-Internet Assigned Numbers Authority" in note


def test_name_servers_and_status_sections_are_rendered(md_gen, full_record):
    note = md_gen.generate(full_record)

    assert "## Name Servers" in note
    assert "A.IANA-SERVERS.NET" in note
    assert "## Domain Status" in note
    assert "clientTransferProhibited" in note


def test_contacts_section_includes_registrant_details(md_gen, full_record):
    note = md_gen.generate(full_record)

    assert "## Contacts" in note
    assert "registrant@example.com" in note
    assert "Los Angeles" in note


def test_attacker_controlled_markdown_is_escaped(md_gen):
    """WHOIS values come from the domain owner and must not inject live markup."""
    record = WhoisRecord.from_response(
        {
            "domain_name": "example.com",
            "domain_registered": "yes",
            "domain_registrar": {"registrar_name": "[click](https://attacker.example)"},
            "registrant_contact": {"name": "<img src=x>", "email_address": "a@b.com"},
        }
    )

    note = md_gen.generate(record)

    assert "[click](https://attacker.example)" not in note
    assert "\\[click\\]" in note  # the brackets are escaped
    assert "<img src=x>" not in note


def test_query_time_is_omitted_to_keep_the_note_deterministic(md_gen, full_record):
    """query_time feeds Note.generate_id; including it would duplicate the note."""
    assert full_record.query_time  # the record carries a timestamp
    assert full_record.query_time not in md_gen.generate(full_record)


def test_empty_sections_are_omitted(md_gen, unregistered_record):
    note = md_gen.generate(unregistered_record)

    assert "## Name Servers" not in note
    assert "## Contacts" not in note
    # The summary table is always present.
    assert "## WHOIS Summary" in note
