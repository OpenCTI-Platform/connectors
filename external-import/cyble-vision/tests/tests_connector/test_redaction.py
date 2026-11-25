"""Leaked credentials must never reach STIX in plain text by default."""

import json
from pathlib import Path

import pytest
from connector.mappers import map_alert
from connector.mappers.redaction import mask_secret, scrub_text
from connectors_sdk.models import OrganizationAuthor, TLPMarking

AUTHOR = OrganizationAuthor(name="Cyble")
MARKING = TLPMarking(level="amber")
FIXTURES = Path(__file__).parents[1] / "fixtures"
# Every password in the fixtures starts with this.
PASSWORD = "redacted-password"


def _stix(name: str, **kwargs) -> list[dict]:
    alert = json.loads((FIXTURES / name).read_text())
    return [
        entity.to_stix2_object()
        for entity in map_alert(alert, AUTHOR, MARKING, **kwargs)
    ]


@pytest.mark.parametrize(
    "fixture",
    ["leaked_credentials.json", "telegram_mentions.json", "stealer_logs.json"],
)
def test_no_password_reaches_stix(fixture):
    assert PASSWORD not in "".join(obj.serialize() for obj in _stix(fixture))


def test_masking_keeps_the_context_analysts_need():
    objects = _stix("leaked_credentials.json")
    note = next(obj for obj in objects if obj["type"] == "note")
    urls = [obj["value"] for obj in objects if obj["type"] == "url"]

    assert urls == ["https://host29.example1.com/storage/manual-book/ss.php"]
    assert "user01" in note["content"]
    assert "Password: re***-2 (39 chars)" in note["content"]
    assert mask_secret(PASSWORD) in note["content"]


def test_telegram_message_pairs_are_masked_in_the_incident():
    incident = next(
        obj for obj in _stix("telegram_mentions.json") if obj["type"] == "incident"
    )
    assert "user1@example.com:re***rd (17 chars)" in incident["description"]


def test_plaintext_is_kept_only_when_opted_in():
    objects = _stix("leaked_credentials.json", include_plaintext_credentials=True)
    note = next(obj for obj in objects if obj["type"] == "note")
    assert PASSWORD in note["content"]


def test_short_secrets_reveal_only_their_length():
    assert mask_secret("abc123") == "*** (6 chars)"


def test_ports_are_not_mistaken_for_passwords():
    text = "see https://admin@example.com:8443/login"
    assert scrub_text(text, []) == text


def test_numeric_combo_passwords_are_masked():
    masked = scrub_text("dump: user@example.com:12345678 and more", [])
    assert "12345678" not in masked
    assert "user@example.com:" in masked


@pytest.mark.parametrize(
    "text, secret",
    [
        ('{"password": "ExamplePassword42!"}', "ExamplePassword42!"),
        ('{"api_key": "sk-live-example123456"}', "sk-live-example123456"),
        ("DB_PASSWORD = 'correct horse battery'", "correct horse battery"),
        ('cfg = {"token": "abc\\"def123456"}', "def123456"),
        ('headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9"}', "eyJhbGci"),
    ],
)
def test_quoted_assignments_in_source_code_are_masked(text, secret):
    masked = scrub_text(text, [])
    assert secret not in masked
    assert "chars)" in masked


def test_quoted_header_masking_stops_at_the_closing_quote():
    masked = scrub_text('{"Cookie": "sid=abc123def456", "user": "alice"}', [])
    assert "abc123def456" not in masked
    assert '"user": "alice"' in masked


@pytest.mark.parametrize(
    "key", ["api_key", "apiKey", "x-api-key", "access_key", "private_key"]
)
def test_api_key_fields_are_masked_everywhere(key):
    alert = json.loads((FIXTURES / "telegram_mentions.json").read_text())
    alert["data"][key] = "sk-live-0123456789abcdef"
    alert["data"]["message"] = "key is sk-live-0123456789abcdef"
    text = "".join(
        entity.to_stix2_object().serialize()
        for entity in map_alert(alert, AUTHOR, MARKING)
    )
    assert "sk-live-0123456789abcdef" not in text


def test_short_passwords_are_masked_as_whole_words_only():
    alert = json.loads((FIXTURES / "telegram_mentions.json").read_text())
    alert["data"]["password"] = "pw42"
    alert["data"]["message"] = "login pw42 for admin; npw42x is unrelated"
    text = "".join(
        entity.to_stix2_object().serialize()
        for entity in map_alert(alert, AUTHOR, MARKING)
    )
    assert " pw42 " not in text
    assert "npw42x" in text


@pytest.mark.parametrize(
    "text, secret",
    [
        ("leaked token=ghp_abcdef1234567890 in repo", "ghp_abcdef1234567890"),
        ("api_key: sk-live-0123456789abcdef", "sk-live-0123456789abcdef"),
        ("Cookie: session=abc123def456; csrftoken=zzz999yyy", "csrftoken=zzz999yyy"),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload", "eyJhbGciOiJIUzI1NiJ9"),
    ],
)
def test_labeled_tokens_and_headers_are_masked(text, secret):
    masked = scrub_text(text, [])
    assert secret not in masked
    assert "chars)" in masked


def test_token_label_masking_keeps_ordinary_words():
    text = "The token economy grew; see https://example.com/tokens"
    assert scrub_text(text, []) == text
