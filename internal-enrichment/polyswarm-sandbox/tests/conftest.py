"""Shared fixtures for polyswarm-sandbox unit tests."""

import os
import subprocess
import sys

import pytest
import vcr

# Add src/ to path
SRC_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "src")
sys.path.insert(0, os.path.abspath(SRC_DIR))


# stix2-validator >=3.3 ships without the OASIS STIX 2.1 JSON schemas in its
# wheel but still looks for them at <install>/schemas-<version>/schemas/.
# Fetch them once into a cache dir and patch ValidationOptions so every
# validate_string() call has a schema_dir to consult.
_SCHEMA_REPO = "https://github.com/oasis-open/cti-stix2-json-schemas.git"
_SCHEMA_CACHE = os.path.expanduser(
    "~/.cache/polyswarm-stix-tests/cti-stix2-json-schemas"
)


def _ensure_stix21_schemas():
    if not os.path.isdir(_SCHEMA_CACHE):
        os.makedirs(os.path.dirname(_SCHEMA_CACHE), exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", _SCHEMA_REPO, _SCHEMA_CACHE],
            check=True,
            capture_output=True,
        )
    # OASIS repo master holds STIX 2.1 schemas directly under schemas/
    return os.path.join(_SCHEMA_CACHE, "schemas")


@pytest.fixture(scope="session", autouse=True)
def _patch_stix_validator_schema_dir():
    try:
        from stix2validator import validator as validator_module
    except ImportError:
        yield
        return
    schema_dir = _ensure_stix21_schemas()
    original_get_error_generator = validator_module._get_error_generator

    def patched(name, obj, sd=None, version=None, default="core"):
        if sd is None:
            sd = schema_dir
        if version is None:
            return original_get_error_generator(name, obj, sd, default=default)
        return original_get_error_generator(
            name, obj, sd, version=version, default=default
        )

    validator_module._get_error_generator = patched
    yield
    validator_module._get_error_generator = original_get_error_generator


class _StubLogger:
    """No-op logger matching connector_logger interface."""

    def info(self, msg, *args, **kwargs):
        pass

    def warning(self, msg, *args, **kwargs):
        pass

    def error(self, msg, *args, **kwargs):
        pass

    def debug(self, msg, *args, **kwargs):
        pass


class StubHelper:
    """Minimal stand-in for OpenCTIConnectorHelper.

    Provides no-op logging and a fake API surface so unit tests can run
    without a live OpenCTI instance.  Bundle/send calls return deterministic
    values for assertion convenience.
    """

    connect_scope = "Artifact"
    connect_log_level = "info"
    config = {}
    connector_logger = _StubLogger()

    class _API:
        class _Observable:
            def add_file(self, **kwargs):
                pass

            def update_field(self, **kwargs):
                pass

        stix_cyber_observable = _Observable()

    api = _API()

    def log_info(self, msg):
        pass

    def log_warning(self, msg):
        pass

    def log_error(self, msg):
        pass

    def log_debug(self, msg):
        pass

    def stix2_create_bundle(self, objects):
        return {"type": "bundle", "spec_version": "2.1", "objects": objects}

    def send_stix2_bundle(self, bundle, **kwargs):
        return ["bundle-1"]

    @staticmethod
    def check_max_tlp(markings, max_tlp):
        return True


@pytest.fixture
def stub_helper():
    return StubHelper()


# ── polykg mock ────────────────────────────────────────────────────────────────

CANNED_PROFILES = {
    "dtrack": {
        "family": "DTrack",
        "description": "DTrack is a modular backdoor developed by the Lazarus group.",
        "malware_type": ["Backdoor"],
        "actors": ["Lazarus"],
        "origin_locations": ["North Korea"],
        "target_locations": ["Germany", "India", "South Korea", "United States"],
        "verticals_targeted": ["Financial", "Government"],
        "related_malware": ["ATMDtrack", "Maui"],
        "target_cves": [],
        "programming_languages": [],
        "systems_targeted": ["Windows"],
        "aliases": [],
    },
    "wannacry": {
        "family": "WannaCry",
        "description": "WannaCry is ransomware exploiting EternalBlue.",
        "malware_type": ["Ransomware"],
        "actors": ["Lazarus"],
        "origin_locations": ["North Korea"],
        "target_locations": ["Worldwide"],
        "verticals_targeted": ["Healthcare", "Government"],
        "related_malware": [],
        "target_cves": ["CVE-2017-0144"],
        "programming_languages": ["C++"],
        "systems_targeted": ["Windows"],
        "aliases": ["WCry", "WannaCrypt"],
    },
}


class _MockResponse:
    """Minimal requests.Response stand-in for polykg API mocks."""

    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self._data = data or {}

    def json(self):
        return self._data


@pytest.fixture
def polykg_mock(monkeypatch):
    """Monkeypatch requests.post in stix_builder to serve canned profiles.

    Intercepts POST calls to ``/v3/kg/profile`` and returns pre-built
    profile dicts from CANNED_PROFILES, keyed by lower-cased family name.
    Also resets the polykg circuit breaker so prior test failures don't bleed.
    """
    import connector.stix_builder as sb_module

    # Reset circuit breaker
    sb_module.StixBuilder._POLYKG_CIRCUIT_OPEN = False
    sb_module.StixBuilder._POLYKG_CIRCUIT_OPENED_AT = None

    def _mock_post(url, json=None, headers=None, timeout=None, **kwargs):
        if "/v3/kg/profile" in str(url):
            family_name = (json or {}).get("family_name", "")
            key = family_name.lower()
            if key in CANNED_PROFILES:
                return _MockResponse(200, CANNED_PROFILES[key])
            return _MockResponse(404)
        return _MockResponse(404)

    monkeypatch.setattr(sb_module.requests, "post", _mock_post)
    yield CANNED_PROFILES


# ── VCR cassette fixtures ─────────────────────────────────────────────────────

CASSETTE_DIR = os.path.join(os.path.dirname(__file__), "cassettes")


def _scrub_authorization(request):
    """Remove Authorization header from recorded VCR cassettes."""
    if "Authorization" in request.headers:
        request.headers["Authorization"] = "SCRUBBED"
    return request


@pytest.fixture
def vcr_instance():
    """Pre-configured VCR instance shared across VCR-based tests."""
    return vcr.VCR(
        cassette_library_dir=CASSETTE_DIR,
        record_mode="none",
        before_record_request=_scrub_authorization,
        decode_compressed_response=True,
        match_on=["method", "scheme", "host", "port", "path"],
    )


# Well-known hashes used in cassettes
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
WANNACRY_SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
SAMPLE_SHA256 = "1e87db50d26931e239ffc34b4a1f59cdbcbf11f1bbb7c2007741adad05c62643"
RHADAMANTHYS_SHA256 = "7c34cccd3f58c144f561493c511a1a96a227cba58d4e1a737c4cd1b3a8a407ff"
