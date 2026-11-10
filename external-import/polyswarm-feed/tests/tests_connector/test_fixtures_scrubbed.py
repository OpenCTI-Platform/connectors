"""Checks that the recorded fixtures carry no credentials or account data.

Also unit tests the scrubber in ``tests/tools/scrub_fixtures.py`` against
synthetic inputs. Fake secrets are assembled at runtime so this file itself
does not trip secret scanners.

If POLYSWARM_API_KEY or POLYSWARM_ACCOUNT_NUMBER are set in the environment,
the fixtures are also checked for those literal values.
"""

import base64
import importlib.util
import json
import os
import re
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
SCRUBBER_PATH = TESTS_DIR / "tools" / "scrub_fixtures.py"


def _load_scrubber():
    spec = importlib.util.spec_from_file_location("scrub_fixtures", SCRUBBER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scrub = _load_scrubber()

JSON_FIXTURES = sorted(FIXTURES_DIR.glob("*.json"))
ALL_FIXTURE_FILES = sorted(p for p in FIXTURES_DIR.iterdir() if p.is_file())

HEX_TOKEN_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])")

# A small set of rules modelled on common gitleaks detections.
GITLEAKS_LIKE_RULES = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "aws access key id": re.compile(
        r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}"
    ),
    "aws secret assignment": re.compile(
        r"(?i)aws_?secret_?access_?key\W{0,4}[A-Za-z0-9/+=]{40}"
    ),
    "slack token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "github token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    "generic secret assignment": re.compile(
        r"(?i)\"?(?:api[_-]?key|secret|token|password|passwd)\"?\s*[:=]\s*"
        r"\"(?!REDACTED)[A-Za-z0-9/+=_-]{16,}\""
    ),
    "basic auth header": re.compile(r"(?i)\bbasic\s+(?!REDACTED)[A-Za-z0-9+/]{16,}=*"),
    "bearer header": re.compile(r"(?i)\bbearer\s+(?!REDACTED)[A-Za-z0-9\-._~+/]{16,}"),
    "fernet cursor": re.compile(r"gAAAAA[A-Za-z0-9_\-]{20,}"),
}


def _walk_strings(value, field=None):
    """Yield (field name, string) for every string in a JSON value."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk_strings(v, str(k).lower())
    elif isinstance(value, list):
        for v in value:
            yield from _walk_strings(v, field)
    elif isinstance(value, str):
        yield field, value


def _walk_items(value):
    """Yield (key, value) for every dict entry in a JSON value."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k).lower(), v
            yield from _walk_items(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_items(v)


def _ids(paths):
    return [p.name for p in paths]


@pytest.fixture(params=JSON_FIXTURES, ids=_ids(JSON_FIXTURES))
def fixture_json(request):
    with open(request.param, encoding="utf-8") as f:
        return request.param.name, json.load(f)


@pytest.fixture(params=ALL_FIXTURE_FILES, ids=_ids(ALL_FIXTURE_FILES))
def fixture_text(request):
    return request.param.name, request.param.read_text(encoding="utf-8")


# -- fixture content checks -------------------------------------------------


def test_fixtures_exist():
    names = {p.name for p in JSON_FIXTURES}
    assert "taxii_discovery.json" in names
    assert "hunt_live_page.synthetic.json" in names
    assert (FIXTURES_DIR / "README.md").is_file()


def test_fixtures_are_ascii(fixture_text):
    name, text = fixture_text
    assert text.isascii(), name


def test_no_account_number(fixture_text):
    name, text = fixture_text
    account = os.environ.get("POLYSWARM_ACCOUNT_NUMBER")
    if account:
        assert account not in text, name
    for match in scrub.FOURTEEN_DIGITS_RE.findall(text):
        assert scrub.is_timestamp14(match), f"{name}: 14 digit number {match[:2]}..."


def test_no_api_key_literal(fixture_text):
    name, text = fixture_text
    key = os.environ.get("POLYSWARM_API_KEY")
    if not key:
        pytest.skip("POLYSWARM_API_KEY not set")
    assert key not in text, name
    account = os.environ.get("POLYSWARM_ACCOUNT_NUMBER")
    if account:
        basic = base64.b64encode(f"{account}:{key}".encode()).decode()
        assert basic not in text, name


def test_auth_like_fields_hold_no_values(fixture_json):
    name, data = fixture_json
    for key, value in _walk_items(data):
        if key in scrub.AUTH_FIELD_NAMES:
            assert value in (None, "", scrub.REDACTED_FIELD), f"{name}: {key}"


def test_long_hex_only_in_hash_fields(fixture_json):
    """The API key is 32 lowercase hex, the same form as an MD5.

    So every long hex token must sit in a field that is expected to hold a
    file hash (or inside a URL path, which the scrubber only keeps when it is
    not presigned).
    """
    name, data = fixture_json
    for field, text in _walk_strings(data):
        stripped = scrub.URL_RE.sub(" ", text)
        for token in HEX_TOKEN_RE.findall(stripped):
            assert field in scrub.HASH_FIELD_NAMES, f"{name}: hex token in {field}"
            if field == "tlsh":
                continue
            assert len(token) in scrub.HASH_LENGTHS, f"{name}: odd hex in {field}"


def test_no_presigned_urls(fixture_text):
    name, text = fixture_text
    for url in scrub.URL_RE.findall(text):
        assert not scrub.PRESIGNED_MARKERS.search(url), name


def test_no_aws_key_ids(fixture_text):
    name, text = fixture_text
    assert not scrub.AWS_KEY_ID_RE.search(text), name


def test_no_emails(fixture_text):
    name, text = fixture_text
    assert not scrub.EMAIL_RE.search(text), name


def test_gitleaks_like_rules(fixture_text):
    name, text = fixture_text
    for rule, pattern in GITLEAKS_LIKE_RULES.items():
        assert not pattern.search(text), f"{name}: {rule}"


def test_scrubber_source_has_no_secrets():
    text = SCRUBBER_PATH.read_text(encoding="utf-8")
    for rule, pattern in GITLEAKS_LIKE_RULES.items():
        assert not pattern.search(text), rule
    assert not scrub.FOURTEEN_DIGITS_RE.search(text)


def test_fixtures_are_already_scrubbed(fixture_json):
    """Running the scrubber again changes nothing."""
    name, data = fixture_json
    scrubber = scrub.Scrubber()
    assert scrubber.scrub(data) == data, name
    assert not scrubber.counts, f"{name}: {dict(scrubber.counts)}"


# -- scrubber unit tests ----------------------------------------------------

FAKE_KEY = "ab" * 16
FAKE_ACCOUNT = "123456" + "78901234"
FAKE_AWS_ID = "AKIA" + "Q" * 16
FAKE_STS_ID = "ASIA" + "R" * 16
FAKE_JWT = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12
FAKE_CURSOR = "gAAAAA" + "Bq8yZ" * 10


@pytest.fixture
def scrubber():
    return scrub.Scrubber(api_key=FAKE_KEY, account_number=FAKE_ACCOUNT)


def test_scrub_api_key(scrubber):
    out = scrubber.scrub({"note": f"key={FAKE_KEY};", "nested": [FAKE_KEY]})
    assert FAKE_KEY not in json.dumps(out)
    assert out["nested"] == [scrub.REDACTED_API_KEY]
    assert scrubber.counts["api_key"] == 2


def test_scrub_basic_credentials(scrubber):
    raw = base64.b64encode(f"{FAKE_ACCOUNT}:{FAKE_KEY}".encode()).decode()
    out = scrubber.scrub_string(f"Basic {raw}")
    assert raw not in out
    assert FAKE_ACCOUNT not in out
    out = scrub.Scrubber().scrub_string("Basic " + "QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
    assert out == "Basic " + scrub.REDACTED_TOKEN


def test_scrub_account_number(scrubber):
    out = scrubber.scrub({"username": FAKE_ACCOUNT, "text": f"acct {FAKE_ACCOUNT}"})
    assert out == {"username": "000000000000", "text": "acct 000000000000"}


def test_scrub_unknown_fourteen_digit_number_but_not_timestamps():
    s = scrub.Scrubber()
    assert s.scrub_string("98765432109876") == scrub.REDACTED_ACCOUNT_NUMBER
    assert s.scrub_string("20180921112649") == "20180921112649"
    md5_like = "a" + "12345678901234" + "b" * 17
    assert s.scrub_string(md5_like) == md5_like


@pytest.mark.parametrize(
    "marker",
    [
        "X-Amz-Signature=abc&X-Amz-Credential=def",
        "Signature=abc&Expires=123",
        "AWSAccessKeyId=abc",
        "Credential=abc",
    ],
)
def test_scrub_presigned_url(marker):
    s = scrub.Scrubber()
    url = "https://bucket.s3.amazonaws.com/path/file.bin?" + marker
    out = s.scrub({"download_url": url, "text": f"get {url} now"})
    assert out == {
        "download_url": scrub.REDACTED_URL,
        "text": f"get {scrub.REDACTED_URL} now",
    }
    assert s.counts["presigned_url"] == 2


def test_plain_url_is_kept():
    url = "https://api.polyswarm.network/v3/stix/trustgroup"
    assert scrub.Scrubber().scrub_string(url) == url


def test_scrub_aws_key_ids():
    s = scrub.Scrubber()
    out = s.scrub_string(f"{FAKE_AWS_ID} {FAKE_STS_ID}")
    assert out == f"{scrub.REDACTED_AWS_KEY_ID} {scrub.REDACTED_AWS_KEY_ID}"


def test_scrub_email():
    s = scrub.Scrubber()
    assert s.scrub({"contact": "someone@example.com"}) == {
        "contact": scrub.REDACTED_EMAIL
    }


def test_scrub_bearer_and_jwt():
    s = scrub.Scrubber()
    assert s.scrub_string("Bearer abc.def-ghi") == "Bearer " + scrub.REDACTED_TOKEN
    assert s.scrub_string(FAKE_JWT) == scrub.REDACTED_TOKEN


def test_scrub_auth_fields():
    s = scrub.Scrubber()
    out = s.scrub({"Authorization": "anything", "X-Billing-ID": "1", "token": None})
    assert out == {
        "Authorization": "REDACTED",
        "X-Billing-ID": "REDACTED",
        "token": None,
    }


def test_scrub_cursor_is_consistent():
    s = scrub.Scrubber()
    page1 = s.scrub({"more": True, "next": FAKE_CURSOR})
    again = s.scrub({"next": FAKE_CURSOR})
    other = s.scrub({"offset": FAKE_CURSOR + "x"})
    assert page1["next"] == again["next"] == "REDACTED_CURSOR_1"
    assert other["offset"] == "REDACTED_CURSOR_2"


def test_anonymize_hunt_page():
    s = scrub.Scrubber(anonymize_hunt=True)
    hit = {
        "id": "11111111111111111",
        "instance_id": "22222222222222222",
        "livescan_id": "33333333333333333",
        "rule_name": "watch_some_company",
        "sha256": "0" * 64,
    }
    out = s.scrub({"result": [hit, dict(hit, id="44444444444444444")]})
    first, second = out["result"]
    assert first["rule_name"] == second["rule_name"] == "example_rule_1"
    assert first["id"] != second["id"]
    assert first["livescan_id"] == second["livescan_id"]
    assert len(first["id"]) == len(hit["id"])
    assert first["sha256"] == hit["sha256"]


def test_hashes_are_untouched(scrubber):
    stix = {
        "type": "file",
        "hashes": {"MD5": "e0480c65d25e41f751bdf931b2d4771d", "SHA-1": "0" * 40},
        "pattern": "[file:hashes.MD5 = 'e0480c65d25e41f751bdf931b2d4771d']",
    }
    assert scrubber.scrub(stix) == stix
    assert not scrubber.counts


def test_report_flags_hex_outside_hash_fields():
    s = scrub.Scrubber()
    s.report_suspicious({"description": "f" * 32, "md5": "f" * 32})
    assert s.findings == [("$.description", "32 char hex outside a hash field")]
