"""Scrub raw PolySwarm API captures before they become test fixtures.

Usage:
    POLYSWARM_API_KEY=... POLYSWARM_ACCOUNT_NUMBER=... \
        python scrub_fixtures.py RAW_DIR OUT_DIR [--anonymize-hunt]

Every ``*.json`` file in RAW_DIR is loaded, scrubbed and written to OUT_DIR
with the same name. The API key and account number are read from the
environment (never from the command line, so they do not land in shell
history) and are replaced wherever they appear, including inside longer
strings and inside base64 encoded HTTP Basic credentials.

Categories handled:
    api_key          literal API key value -> REDACTED_API_KEY
    account_number   literal account number, and any other bare 14 digit
                     number that is not a YYYYMMDDhhmmss timestamp
                     -> 000000000000
    presigned_url    any URL carrying X-Amz-*, Signature=, Expires=,
                     AWSAccessKeyId or Credential= -> REDACTED_URL
    aws_key_id       AKIA... / ASIA... access key ids -> REDACTED_AWS_KEY_ID
    email            email addresses -> REDACTED_EMAIL
    bearer_token     "Bearer <token>", "Basic <b64>" and JWTs -> redacted
    auth_field       value of any auth-like field (authorization, api_key,
                     token, password, ...) -> REDACTED
    cursor           opaque Fernet paging cursors (next / offset)
                     -> REDACTED_CURSOR_<n>, consistent within one run so a
                     page's cursor still matches the request for the next
    hunt_*           with --anonymize-hunt: live-hunt hit ids, instance ids,
                     ruleset ids and rule names are replaced with stable
                     synthetic values (rule names can reveal what an account
                     is monitoring)

Anything else that looks sensitive (long high entropy tokens outside hash
fields, URLs with query strings, IPv4 addresses, unexpected long digit runs)
is reported on stderr but left in place for a human to decide.
"""

import argparse
import base64
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

REDACTED_API_KEY = "REDACTED_API_KEY"
REDACTED_ACCOUNT_NUMBER = "000000000000"
REDACTED_URL = "https://example.invalid/redacted"
REDACTED_AWS_KEY_ID = "REDACTED_AWS_KEY_ID"
REDACTED_EMAIL = "REDACTED_EMAIL"
REDACTED_TOKEN = "REDACTED_TOKEN"
REDACTED_FIELD = "REDACTED"

PRESIGNED_MARKERS = re.compile(
    r"X-Amz-|Signature=|Expires=|AWSAccessKeyId|Credential=", re.IGNORECASE
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
AWS_KEY_ID_RE = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+(?!REDACTED)[A-Za-z0-9\-._~+/]+=*")
BASIC_RE = re.compile(r"(?i)\bbasic\s+(?!REDACTED)[A-Za-z0-9+/]{8,}=*")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
FERNET_RE = re.compile(r"gAAAAA[A-Za-z0-9_\-]{20,}={0,2}")
FOURTEEN_DIGITS_RE = re.compile(r"(?<![0-9A-Za-z])\d{14}(?![0-9A-Za-z])")

AUTH_FIELD_NAMES = {
    "authorization",
    "proxy-authorization",
    "api_key",
    "apikey",
    "api-key",
    "x-api-key",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "cookie",
    "set-cookie",
    "x-billing-id",
    "aws_secret_access_key",
    "aws_session_token",
}
CURSOR_FIELD_NAMES = {"next", "offset"}

# Fields whose values are expected to be file hashes or other hex digests
# (engine definition versions are sometimes a 32 char digest), so long hex
# there is fine.
HASH_FIELD_NAMES = {
    "analysis_definition_version",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "sha-1",
    "sha-256",
    "sha-512",
    "ssdeep",
    "tlsh",
    "name",
    "aliases",
    "pattern",
}
HASH_LENGTHS = {32, 40, 64, 128}

# Report-only heuristics.
LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
STIX_ID_RE = re.compile(r"[a-z0-9-]+--" + UUID_RE.pattern)

HUNT_ID_FIELDS = ("id", "instance_id", "livescan_id")


def is_timestamp14(digits: str) -> bool:
    """True when a 14 digit run parses as a YYYYMMDDhhmmss timestamp."""
    try:
        datetime.strptime(digits, "%Y%m%d%H%M%S")
    except ValueError:
        return False
    return True


class Scrubber:
    """Holds the secrets to look for and the per-run replacement state."""

    def __init__(self, api_key=None, account_number=None, anonymize_hunt=False):
        self.api_key = api_key or None
        self.account_number = account_number or None
        self.anonymize_hunt = anonymize_hunt
        self.counts = Counter()
        self.findings = []
        self._cursors = {}
        self._hunt_ids = {}
        self._hunt_rules = {}
        self._basic_secrets = self._basic_variants()

    def _basic_variants(self):
        """Base64 forms of 'account:key' that an HTTP Basic header would carry."""
        if not (self.api_key and self.account_number):
            return []
        raw = f"{self.account_number}:{self.api_key}".encode()
        return [base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()]

    # -- string level ------------------------------------------------------

    def _sub(self, pattern, repl, text, category):
        new, n = pattern.subn(repl, text)
        if n:
            self.counts[category] += n
        return new

    def _cursor_repl(self, match):
        token = match.group(0)
        if token not in self._cursors:
            self._cursors[token] = f"REDACTED_CURSOR_{len(self._cursors) + 1}"
        return self._cursors[token]

    def _url_repl(self, match):
        url = match.group(0)
        if PRESIGNED_MARKERS.search(url):
            self.counts["presigned_url"] += 1
            return REDACTED_URL
        return url

    def _number_repl(self, match):
        digits = match.group(0)
        if is_timestamp14(digits):
            return digits
        self.counts["account_number"] += 1
        return REDACTED_ACCOUNT_NUMBER

    def scrub_string(self, text: str) -> str:
        """Apply every string level rule to one string."""
        for secret in self._basic_secrets:
            if secret in text:
                self.counts["api_key"] += text.count(secret)
                text = text.replace(secret, REDACTED_TOKEN)
        if self.api_key and self.api_key in text:
            self.counts["api_key"] += text.count(self.api_key)
            text = text.replace(self.api_key, REDACTED_API_KEY)
        if self.account_number and self.account_number in text:
            self.counts["account_number"] += text.count(self.account_number)
            text = text.replace(self.account_number, REDACTED_ACCOUNT_NUMBER)
        text = URL_RE.sub(self._url_repl, text)
        text = self._sub(JWT_RE, REDACTED_TOKEN, text, "bearer_token")
        text = self._sub(BEARER_RE, "Bearer " + REDACTED_TOKEN, text, "bearer_token")
        text = self._sub(BASIC_RE, "Basic " + REDACTED_TOKEN, text, "bearer_token")
        text = self._sub(AWS_KEY_ID_RE, REDACTED_AWS_KEY_ID, text, "aws_key_id")
        text = self._sub(EMAIL_RE, REDACTED_EMAIL, text, "email")
        new = FERNET_RE.sub(self._cursor_repl, text)
        if new != text:
            self.counts["cursor"] += 1
            text = new
        text = FOURTEEN_DIGITS_RE.sub(self._number_repl, text)
        return text

    # -- structure level ---------------------------------------------------

    def _anonymize_hit(self, hit: dict) -> dict:
        hit = dict(hit)
        for field in HUNT_ID_FIELDS:
            value = hit.get(field)
            if isinstance(value, str) and value:
                key = (field, value)
                if key not in self._hunt_ids:
                    n = len([k for k in self._hunt_ids if k[0] == field]) + 1
                    prefix = {"id": "1", "instance_id": "2", "livescan_id": "3"}[field]
                    self._hunt_ids[key] = f"{prefix}{n:016d}"
                    self.counts[f"hunt_{field}"] += 1
                hit[field] = self._hunt_ids[key]
        rule = hit.get("rule_name")
        if isinstance(rule, str) and rule:
            if rule not in self._hunt_rules:
                self._hunt_rules[rule] = f"example_rule_{len(self._hunt_rules) + 1}"
                self.counts["hunt_rule_name"] += 1
            hit["rule_name"] = self._hunt_rules[rule]
        return hit

    def scrub(self, value, field=None):
        """Recursively scrub a decoded JSON value."""
        if isinstance(value, dict):
            if (
                self.anonymize_hunt
                and isinstance(value.get("result"), list)
                and any(
                    isinstance(h, dict) and "livescan_id" in h for h in value["result"]
                )
            ):
                value = dict(value)
                value["result"] = [
                    self._anonymize_hit(h) if isinstance(h, dict) else h
                    for h in value["result"]
                ]
            out = {}
            for k, v in value.items():
                lk = str(k).lower()
                if lk in AUTH_FIELD_NAMES and v not in (None, "", REDACTED_FIELD):
                    self.counts["auth_field"] += 1
                    out[k] = REDACTED_FIELD
                    continue
                out[k] = self.scrub(v, field=lk)
            return out
        if isinstance(value, list):
            return [self.scrub(v, field=field) for v in value]
        if isinstance(value, str):
            return self.scrub_string(value)
        return value

    # -- reporting ---------------------------------------------------------

    def report_suspicious(self, value, path="$", field=None):
        """Collect things that look sensitive but no rule replaced."""
        if isinstance(value, dict):
            for k, v in value.items():
                self.report_suspicious(v, f"{path}.{k}", str(k).lower())
            return
        if isinstance(value, list):
            for i, v in enumerate(value):
                self.report_suspicious(v, f"{path}[{i}]", field)
            return
        if not isinstance(value, str):
            return
        for url in URL_RE.findall(value):
            if "?" in url and not url.startswith(REDACTED_URL):
                self.findings.append((path, "url with query string"))
        if IPV4_RE.search(value) and not (field or "").endswith("version"):
            self.findings.append((path, "ipv4 address"))
        if STIX_ID_RE.fullmatch(value) or UUID_RE.fullmatch(value):
            return
        for token in LONG_TOKEN_RE.findall(URL_RE.sub(" ", value)):
            is_hex = re.fullmatch(r"[0-9a-fA-F]+", token) is not None
            if is_hex and len(token) in HASH_LENGTHS:
                if field not in HASH_FIELD_NAMES:
                    self.findings.append(
                        (path, f"{len(token)} char hex outside a hash field")
                    )
                continue
            if field in HASH_FIELD_NAMES:
                continue
            if token.startswith("REDACTED"):
                continue
            self.findings.append((path, f"long token ({len(token)} chars)"))


def scrub_file(scrubber: Scrubber, src: Path, dst: Path) -> None:
    with open(src, encoding="utf-8") as f:
        data = json.load(f)
    data = scrubber.scrub(data)
    scrubber.report_suspicious(data, path=src.name)
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=True)
        f.write("\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("raw_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--anonymize-hunt", action="store_true")
    args = parser.parse_args(argv)

    api_key = os.environ.get("POLYSWARM_API_KEY")
    account = os.environ.get("POLYSWARM_ACCOUNT_NUMBER")
    if not api_key or not account:
        print(
            "warning: POLYSWARM_API_KEY or POLYSWARM_ACCOUNT_NUMBER not set, "
            "literal secret replacement is limited to pattern rules",
            file=sys.stderr,
        )
    scrubber = Scrubber(api_key, account, anonymize_hunt=args.anonymize_hunt)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for src in sorted(args.raw_dir.glob("*.json")):
        scrub_file(scrubber, src, args.out_dir / src.name)

    print("replacements:", file=sys.stderr)
    for category, n in sorted(scrubber.counts.items()):
        print(f"  {category}: {n}", file=sys.stderr)
    print(f"suspicious (left in place): {len(scrubber.findings)}", file=sys.stderr)
    for path, why in scrubber.findings:
        print(f"  {path}: {why}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
