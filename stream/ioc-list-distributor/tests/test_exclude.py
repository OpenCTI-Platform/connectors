"""Checks for EXPORT_IP_EXCLUDE / EXPORT_DOMAIN_EXCLUDE: what is never exported, and what is.

Run: python tests/test_exclude.py (or pytest).
"""

import logging
import os
import sys
import tempfile
from pathlib import Path

os.environ["DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from common import config  # noqa: E402
from ioc_distributor.exporter import STATE_FILE, FeedExporter  # noqa: E402

KEYS = [
    "EXPORT_IP_EXCLUDE",
    "EXPORT_DOMAIN_EXCLUDE",
    "EXPORT_IP_EXCLUDE_FILE",
    "EXPORT_DOMAIN_EXCLUDE_FILE",
    "EXPORT_MAX_ENTRIES",
    "EXPORT_MAX_DROP_PERCENT",
    "EXPORT_URL_STRIP_SCHEME",
    "EXPORT_DROP_NON_PUBLIC_IPS",
    "CUSTOM_FEED1_ENABLED",
    "CUSTOM_FEED1_NAME",
    "CUSTOM_FEED1_MAX_ENTRIES",
    "EXPORT_MAX_ENTRIES_DOMAIN",
    "EXPORT_IP_MIN_PREFIX_V4",
]

ALLOW_ENV = dict(
    EXPORT_IP_EXCLUDE="8.8.8.8, 1.1.1.0/24, 2001:4860:4860::8888",
    EXPORT_DOMAIN_EXCLUDE="filigran.io, Microsoft.com., octi.filigran.io",
)


def _settings(**env):
    for key in KEYS:
        os.environ.pop(key, None)
    os.environ.update({k: str(v) for k, v in env.items()})
    return config.export_settings()


class _FakeStore:
    def __init__(self, rows):
        self.rows = rows  # {ioc_type: [value, ...]} in ranking order

    def select_for_export(self, ioc_type, base_attribute, cutoff, now, sort_order):
        return [(v, None) for v in self.rows.get(ioc_type, [])]

    def purge_older_than(self, cutoff):
        return 0


def _clean():
    for d in (config.FEEDS_DIR, config.BACKUP_DIR, config.TMP_DIR):
        os.makedirs(d, exist_ok=True)
        for name in os.listdir(d):
            os.remove(os.path.join(d, name))
    state = os.path.join(config.DATA_DIR, STATE_FILE)
    if os.path.exists(state):
        os.remove(state)


def _export(rows, **env):
    """One export; returns ({file name: [lines]}, exporter)."""
    _clean()
    e = FeedExporter(_FakeStore(rows), _settings(EXPORT_MAX_ENTRIES=0, **env))
    e.export_once()
    files = {}
    for name in os.listdir(config.FEEDS_DIR):
        with open(os.path.join(config.FEEDS_DIR, name)) as f:
            files[name] = f.read().splitlines()
    return files, e


def test_ip_exclude_exact_cidr_overlap_and_ipv6():
    rows = {
        "ip": [
            "8.8.8.8",  # exact match: out
            "1.1.1.1",  # inside an excluded /24: out
            "1.1.0.0/23",  # wider range containing the /24: out (would block it)
            "1.1.1.128/25",  # narrower range inside the /24: out
            "2001:4860:4860::8888",  # IPv6 exact: out
            "8.8.4.4",  # neighbour, not excluded: in
            "1.1.2.1",  # just outside the /24: in
            "9.9.9.9",  # in
            "2001:4860:4860::8844",  # IPv6 neighbour: in
        ]
    }
    # min prefix /16 so the /23 reaches the exclude list check (at the default /24 it is "too wide")
    files, e = _export(rows, EXPORT_IP_MIN_PREFIX_V4=16, **ALLOW_ENV)
    assert files["ip.txt"] == sorted(
        ["8.8.4.4", "1.1.2.1", "9.9.9.9", "2001:4860:4860::8844"]
    )
    dropped = e.status()["files"]["ip.txt"]["dropped"]
    assert dropped["count"] == 5 and dropped["by_reason"] == {
        "exclude list": 5
    }  # logged + in /stats


def test_domain_exclude_subdomains_case_and_lookalikes():
    rows = {
        "domain": [
            "filigran.io",  # exact: out
            "docs.filigran.io",  # subdomain: out
            "login.microsoft.com",  # subdomain, exclude list written with capitals + trailing dot: out
            "evilfiligran.io",  # lookalike (no dot boundary): in
            "filigran.io.evil.com",  # excluded name as a label of another domain: in
            "microsoft.com-login.net",  # in
            "example.org",  # in
        ]
    }
    files, e = _export(rows, **ALLOW_ENV)
    assert files["domain.txt"] == sorted(
        [
            "evilfiligran.io",
            "filigran.io.evil.com",
            "microsoft.com-login.net",
            "example.org",
        ]
    )
    dropped = e.status()["files"]["domain.txt"][
        "dropped"
    ]  # domains left out: in /stats like IPs
    assert dropped["count"] == 3 and dropped["by_reason"] == {"exclude list": 3}
    assert {
        "value": "docs.filigran.io",
        "reason": "exclude list: matches filigran.io",
    } in dropped["values"]
    assert {
        "value": "login.microsoft.com",
        "reason": "exclude list: matches microsoft.com",
    } in dropped["values"]


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def test_domain_and_url_exclusions_are_logged():
    """Each excluded domain / URL is logged once with the entry it matched, plus a summary line."""
    rows = {
        "domain": ["docs.filigran.io", "example.org"],
        "url": ["https://filigran.io/blog", "http://8.8.8.8/x", "http://evil.com/a"],
    }
    cap = _Capture()
    root = logging.getLogger()
    old_level = root.level
    root.setLevel(logging.INFO)
    root.addHandler(cap)
    try:
        _export(rows, **ALLOW_ENV)
    finally:
        root.removeHandler(cap)
        root.setLevel(old_level)
    text = "\n".join(cap.lines)
    assert (
        "domain.txt: not exported: docs.filigran.io (exclude list: matches filigran.io)"
        in text
    )
    assert "domain.txt: 1 domain(s) left out (exclude list: 1)" in text
    assert (
        "url.txt: not exported: https://filigran.io/blog (exclude list: matches filigran.io)"
        in text
    )
    assert (
        "url.txt: not exported: http://8.8.8.8/x (exclude list: in 8.8.8.8/32)" in text
    )
    assert "url.txt: 2 URL(s) left out (exclude list: 2)" in text
    assert "example.org" not in text and "evil.com/a" not in text


def test_url_exclude_uses_the_url_host():
    rows = {
        "url": [
            "https://filigran.io/blog",  # host excluded: out
            "http://docs.filigran.io:8443/graphql",  # subdomain + port: out
            "https://LOGIN.Microsoft.com/x",  # host case: out
            "http://filigran.io@evil.com/",  # userinfo trick, real host evil.com: in
            "http://evil.com/filigran.io",  # excluded name only in the path: in
            "http://evil.com/?r=https://filigran.io",  # only in the query: in
            "http://evilfiligran.io/",  # lookalike host: in
        ]
    }
    files, e = _export(rows, **ALLOW_ENV)
    assert e.status()["files"]["url.txt"]["dropped"]["count"] == 3
    assert files["url.txt"] == sorted(
        [
            "filigran.io@evil.com/",
            "evil.com/filigran.io",
            "evil.com/?r=https://filigran.io",
            "evilfiligran.io/",
        ]
    )


def test_url_with_excluded_ip_host_is_left_out():
    """EXPORT_IP_EXCLUDE also applies to url.txt when the URL host is an IP."""
    rows = {
        "url": [
            "http://8.8.8.8/dns-query",  # exact IP in the exclude list: out
            "https://8.8.8.8:443/x",  # with a port: out
            "http://1.1.1.1/x",  # inside 1.1.1.0/24: out
            "http://[2001:4860:4860::8888]/x",  # IPv6 in brackets: out
            "http://[2001:4860:4860:0::8888]/y",  # same IPv6 written differently: out
            "http://8.8.4.4/x",  # neighbour, not excluded: kept
            "http://1.1.2.1/x",  # just outside the /24: kept
            "http://8.8.8.8.evil.com/x",  # a name that starts like the IP: kept
        ]
    }
    files, _ = _export(rows, **ALLOW_ENV)
    assert files["url.txt"] == ["1.1.2.1/x", "8.8.4.4/x", "8.8.8.8.evil.com/x"]


def test_url_ip_host_without_ip_exclude_is_exported():
    files, _ = _export(
        {"url": ["http://8.8.8.8/dns-query"]}, EXPORT_DOMAIN_EXCLUDE="filigran.io"
    )
    assert files["url.txt"] == ["8.8.8.8/dns-query"]


def _write(text):
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


def test_exclude_files_are_read_and_merged_with_env():
    ip_file = _write(
        "# resolvers\n\n8.8.8.8   # Google\n1.1.1.0/24\n  9.9.9.9  \n8.8.8.8\n"
    )
    dom_file = _write("# critical\nFiligran.io.\nmicrosoft.com # M365\n\n")
    s = _settings(
        EXPORT_IP_EXCLUDE="8.8.8.8, 4.4.4.4",
        EXPORT_IP_EXCLUDE_FILE=ip_file,
        EXPORT_DOMAIN_EXCLUDE="example.org",
        EXPORT_DOMAIN_EXCLUDE_FILE=dom_file,
    )
    assert [str(n) for n in s.ip_exclude] == [
        "8.8.8.8/32",
        "4.4.4.4/32",
        "1.1.1.0/24",
        "9.9.9.9/32",
    ]
    assert list(s.domain_exclude) == ["example.org", "filigran.io", "microsoft.com"]
    assert s.exclude_sources["ip"] == {"entries": 4, "from_env": 2, "file": ip_file}
    assert any(
        "IP exclude list: 4 unique entries (2 from the setting, 4 from " in n
        for n in s.notes
    )

    rows = {
        "ip": ["8.8.8.8", "9.9.9.9", "4.4.4.4", "5.5.5.5"],
        "domain": ["a.filigran.io", "login.microsoft.com", "example.org", "bad.com"],
        "url": ["http://9.9.9.9/x", "https://www.filigran.io/y", "http://bad.com/z"],
    }
    files, _ = _export(
        rows,
        EXPORT_IP_EXCLUDE="8.8.8.8, 4.4.4.4",
        EXPORT_IP_EXCLUDE_FILE=ip_file,
        EXPORT_DOMAIN_EXCLUDE="example.org",
        EXPORT_DOMAIN_EXCLUDE_FILE=dom_file,
    )
    assert files["ip.txt"] == ["5.5.5.5"]
    assert files["domain.txt"] == ["bad.com"]
    assert files["url.txt"] == ["bad.com/z"]


def test_file_only_and_empty_file():
    s = _settings(EXPORT_IP_EXCLUDE_FILE=_write("8.8.8.8\n"))
    assert [str(n) for n in s.ip_exclude] == ["8.8.8.8/32"]
    s = _settings(EXPORT_DOMAIN_EXCLUDE_FILE=_write("# nothing yet\n\n"))
    assert s.domain_exclude == ()
    assert s.exclude_sources["domain"]["entries"] == 0


def test_no_file_setting_adds_no_startup_note():
    s = _settings(EXPORT_IP_EXCLUDE="8.8.8.8")
    assert not any("exclude list" in n for n in s.notes)
    assert s.exclude_sources["ip"] == {"entries": 1, "from_env": 1, "file": None}


def test_missing_exclude_file_stops_startup():
    for key in ("EXPORT_IP_EXCLUDE_FILE", "EXPORT_DOMAIN_EXCLUDE_FILE"):
        try:
            _settings(**{key: "/nonexistent/exclude.txt"})
        except SystemExit as exc:
            assert key in str(exc) and "/nonexistent/exclude.txt" in str(exc)
        else:
            raise AssertionError(f"a missing {key} must stop startup")


def test_invalid_ip_in_file_names_the_line():
    path = _write("8.8.8.8\n# comment\nnot-an-ip\n")
    try:
        _settings(EXPORT_IP_EXCLUDE_FILE=path)
    except SystemExit as exc:
        assert "line 3" in str(exc) and "not-an-ip" in str(exc) and path in str(exc)
    else:
        raise AssertionError("an invalid IP in the exclude list file must stop startup")


def test_exclude_applies_before_the_cap_and_to_every_feed():
    # Exclude listed values rank first; they must not take cap slots, and custom feeds are filtered too.
    rows = {
        "domain": ["filigran.io", "a.filigran.io", "one.com", "two.com", "three.com"]
    }
    files, _ = _export(
        rows,
        EXPORT_MAX_ENTRIES_DOMAIN=2,
        CUSTOM_FEED1_ENABLED="true",
        CUSTOM_FEED1_NAME="big",
        CUSTOM_FEED1_MAX_ENTRIES=10,
        **ALLOW_ENV,
    )
    assert files["domain.txt"] == ["one.com", "two.com"]  # 2 real entries, not 0
    assert files["big_domain.txt"] == ["one.com", "three.com", "two.com"]


def test_exclude_wins_even_without_non_public_filter():
    files, _ = _export(
        {"ip": ["8.8.8.8", "9.9.9.9"]}, EXPORT_DROP_NON_PUBLIC_IPS="false", **ALLOW_ENV
    )
    assert files["ip.txt"] == ["9.9.9.9"]


def test_empty_excludes_change_nothing():
    rows = {
        "ip": ["8.8.8.8"],
        "domain": ["filigran.io"],
        "url": ["https://filigran.io/"],
    }
    files, _ = _export(rows)
    assert files["ip.txt"] == ["8.8.8.8"]
    assert files["domain.txt"] == ["filigran.io"]
    assert files["url.txt"] == ["filigran.io/"]


def test_invalid_ip_exclude_stops_startup():
    try:
        _settings(EXPORT_IP_EXCLUDE="8.8.8.8, not-an-ip")
    except SystemExit as exc:
        assert "EXPORT_IP_EXCLUDE" in str(exc)
    else:
        raise AssertionError("an invalid EXPORT_IP_EXCLUDE entry must stop startup")


def test_domain_exclude_entries_are_checked():
    s = _settings(
        EXPORT_DOMAIN_EXCLUDE="com, *.supplier.com, 8.8.8.8, bad/path, ok.example, localhost"
    )
    text = "\n".join(s.warnings)
    assert "'com' has no dot" in text and "'localhost' has no dot" in text
    assert "'8.8.8.8' looks like an IP or CIDR" in text
    assert (
        "'8.8' looks like an IP or CIDR"
        in _settings(EXPORT_DOMAIN_EXCLUDE="8.8").warnings[0]
    )
    assert "'bad/path' contains '/'" in text
    assert "'*.supplier.com'" not in text and "ok.example" not in text
    assert "supplier.com" in s.domain_exclude  # '*.' accepted as the domain itself
    files, _ = _export(
        {"domain": ["a.supplier.com", "supplier.com", "other.org"]},
        EXPORT_DOMAIN_EXCLUDE="*.supplier.com",
    )
    assert files["domain.txt"] == ["other.org"]


def test_domain_exclude_file_warning_names_the_line():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("# own\nfiligran.io\nnet   # typo\n")
    s = _settings(EXPORT_DOMAIN_EXCLUDE_FILE=f.name)
    assert any(f"{f.name} line 3" in w and "'net' has no dot" in w for w in s.warnings)
    assert not any("filigran.io" in w for w in s.warnings)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
