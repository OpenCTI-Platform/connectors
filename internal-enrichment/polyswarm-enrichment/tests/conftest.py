"""Shared fixtures for the PolySwarm enrichment connector test suite."""

import os
import sys
import logging

import pytest
import vcr

# ---------------------------------------------------------------------------
# Path setup: make ``src/`` importable exactly as Docker does.
# ---------------------------------------------------------------------------
SRC_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "src")
sys.path.insert(0, os.path.abspath(SRC_DIR))


# ---------------------------------------------------------------------------
# StubHelper -- lightweight stand-in for OpenCTIConnectorHelper
# ---------------------------------------------------------------------------
class _StubLogger:
    """Minimal logger that satisfies ``helper.connector_logger.error(...)``."""

    def error(self, msg, *args, **kwargs):
        print(f"[STUB-LOGGER-ERROR] {msg}", *args)

    def warning(self, msg, *args, **kwargs):
        print(f"[STUB-LOGGER-WARN] {msg}", *args)

    def info(self, msg, *args, **kwargs):
        print(f"[STUB-LOGGER-INFO] {msg}", *args)

    def debug(self, msg, *args, **kwargs):
        pass


class StubHelper:
    """Drop-in replacement for ``OpenCTIConnectorHelper`` in unit tests."""

    def __init__(self):
        self.connector_logger = _StubLogger()
        self.connect_scope = "stixfile"

    # Logging methods expected by production code
    def log_info(self, msg):
        print(f"[INFO] {msg}")

    def log_warning(self, msg):
        print(f"[WARN] {msg}")

    def log_error(self, msg):
        print(f"[ERROR] {msg}")

    def log_debug(self, msg):
        pass

    # Bundle helpers used by the connector pipeline
    @staticmethod
    def stix2_create_bundle(objects):
        return {"type": "bundle", "objects": objects}

    @staticmethod
    def send_stix2_bundle(bundle, **kwargs):
        return ["bundle-1"]


# ---------------------------------------------------------------------------
# StubConfig -- minimal config matching PolySwarmConfig Pydantic model surface
# ---------------------------------------------------------------------------
class StubConfig:
    """Provides the configuration surface expected by ``ConnectorClient``.

    Duck-types the ``PolySwarmConfig`` Pydantic model so tests don't need
    real environment variables or connectors-sdk installed.
    """

    def __init__(self):
        self.api_key = os.environ.get("POLYSWARM_API_KEY", "test-key-placeholder")
        self.community = "default"
        self.polykg_api_url = "http://fake-polykg:8000"
        self.max_tlp = ""
        self.replace_with_lower_score = True
        self.max_polling_time = 120
        self.ioc_enabled = True
        self.ioc_max_count = 20
        self.ioc_score = 20
        self.ioc_types = ["ip", "domain", "url"]


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def stub_helper():
    return StubHelper()


@pytest.fixture()
def stub_config():
    return StubConfig()


# ---------------------------------------------------------------------------
# Sample polykg profile responses for mocking
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Mock attack-patterns endpoint data (subset for testing)
# ---------------------------------------------------------------------------
MOCK_TTP_DATABASE = {
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact", "description": "Adversaries may encrypt data on target systems."},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact", "description": "Adversaries may delete or remove built-in data and turn off services."},
    "T1489": {"name": "Service Stop", "tactic": "impact", "description": "Adversaries may stop or disable services on a system."},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery", "description": "Adversaries may attempt to get detailed information about the operating system."},
    "T1083": {"name": "File and Directory Discovery", "tactic": "discovery", "description": "Adversaries may enumerate files and directories."},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence", "description": "Adversaries may configure system settings to automatically execute a program during boot or logon."},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "persistence", "description": "Adversaries may achieve persistence by adding a program to a startup folder."},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution", "description": "Adversaries may abuse command and script interpreters."},
    "T1059.001": {"name": "PowerShell", "tactic": "execution", "description": "Adversaries may abuse PowerShell commands and scripts."},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "execution", "description": "Adversaries may abuse the Windows command shell for execution."},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "credential-access", "description": "Adversaries may search for common password storage locations."},
    "T1555.003": {"name": "Credentials from Web Browsers", "tactic": "credential-access", "description": "Adversaries may acquire credentials from web browsers."},
    "T1539": {"name": "Steal Web Session Cookie", "tactic": "credential-access", "description": "Adversaries may steal web session cookies."},
    "T1552.001": {"name": "Credentials In Files", "tactic": "credential-access", "description": "Adversaries may search local file systems for files containing insecurely stored credentials."},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access", "description": "Adversaries may attempt to dump credentials."},
    "T1005": {"name": "Data from Local System", "tactic": "collection", "description": "Adversaries may search local system sources."},
    "T1560": {"name": "Archive Collected Data", "tactic": "collection", "description": "Adversaries may compress and/or encrypt data collected prior to exfiltration."},
    "T1566": {"name": "Phishing", "tactic": "initial-access", "description": "Adversaries may send phishing messages to gain access."},
    "T1204.002": {"name": "Malicious File", "tactic": "execution", "description": "Adversaries may rely upon a user opening a malicious file."},
    "T1055": {"name": "Process Injection", "tactic": "defense-evasion", "description": "Adversaries may inject code into processes."},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "defense-evasion", "description": "Adversaries may use obfuscated files or information to hide artifacts."},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion", "description": "Adversaries may attempt to make a payload difficult to discover or analyze."},
    "T1113": {"name": "Screen Capture", "tactic": "collection", "description": "Adversaries may attempt to take screen captures."},
    "T1125": {"name": "Video Capture", "tactic": "collection", "description": "Adversaries may leverage video capture devices."},
    "T1123": {"name": "Audio Capture", "tactic": "collection", "description": "Adversaries may leverage audio capture devices."},
    "T1056.001": {"name": "Keylogging", "tactic": "collection", "description": "Adversaries may log user keystrokes."},
    "T1119": {"name": "Automated Collection", "tactic": "collection", "description": "Adversaries may use automated techniques for collecting data."},
    "T1091": {"name": "Replication Through Removable Media", "tactic": "lateral-movement", "description": "Adversaries may move onto systems by copying malware to removable media."},
}

MOCK_TYPE_TTP_MAP = {
    "ransomware": ["T1486", "T1490", "T1489", "T1082", "T1083", "T1547.001", "T1059.001", "T1059.003"],
    "stealer": ["T1555", "T1555.003", "T1539", "T1552.001", "T1003", "T1005", "T1560"],
    "trojan": ["T1566", "T1204.002", "T1547", "T1055", "T1140", "T1027"],
    "spyware": ["T1113", "T1125", "T1123", "T1056.001", "T1005", "T1119"],
    "virus": ["T1091", "T1204.002", "T1547"],
}

MOCK_ATTACK_PATTERNS_RESPONSE = {
    "techniques": {
        tid: {"technique_id": tid, **info}
        for tid, info in MOCK_TTP_DATABASE.items()
    },
    "type_mappings": MOCK_TYPE_TTP_MAP,
}


# ---------------------------------------------------------------------------
# Real profiles generated by shifty batch mode (polykg + shifty agent) on
# 2026-03-09.  TTPs enriched from MITRE ATT&CK v18.1 via enrich_ttps().
# To regenerate:  python -m kg.cli profile-generate <family>
# ---------------------------------------------------------------------------
POLYKG_DTRACK_PROFILE = {
    "family": "DTrack",
    "description": "DTrack is a modular Remote Access Trojan (RAT) and backdoor developed by the Lazarus Group for stealthy intelligence gathering and espionage. It features comprehensive data collection capabilities including keylogging, screenshot capture, browser history retrieval, running process monitoring, IP configuration discovery, and network connection enumeration. A specialized variant called ATMDTrack was developed specifically to target ATM systems and steal payment card data. The malware uses encrypted payloads, decryption routines, and obfuscation techniques to evade detection while establishing persistence and exfiltrating collected data.",
    "malware_type": ["Backdoor", "RAT", "Stealer", "Spyware"],
    "actors": ["Lazarus Group", "APT38"],
    "origin_locations": ["North Korea"],
    "programming_languages": [],
    "systems_targeted": ["Windows", "ATM Systems"],
    "target_locations": ["India", "South Korea", "Europe"],
    "verticals_targeted": ["Financial Services", "Banking", "ATM Networks"],
    "related_malware": ["ATMDTrack"],
    "target_cves": [],
    "campaigns": ["Operation DarkSeoul", "Operation Dream Job"],
    "updated": "2026-03-09T09:29:06.773236+00:00",
    "citations": "https://attack.mitre.org/software/S0567/, https://socprime.com/news/dtrack-rat-on-the-service-of-lazarus-group/, https://www.zdnet.com/article/new-north-korean-malware-targeting-atms-spotted-in-india/, https://www.bankinfosecurity.com/kaspersky-dual-use-dtrack-malware-linked-to-atm-thefts-a-13144, https://malpedia.caad.fkie.fraunhofer.de/details/win.dtrack",
    "ttps": [
        {"technique_id": "T1005", "name": "Data from Local System", "tactic": ""},
        {"technique_id": "T1074.001", "name": "Data Staged: Local Data Staging", "tactic": ""},
        {"technique_id": "T1140", "name": "Deobfuscate/Decode Files or Information", "tactic": ""},
        {"technique_id": "T1027.009", "name": "Obfuscated Files or Information: Embedded Payloads", "tactic": ""},
        {"technique_id": "T1082", "name": "System Information Discovery", "tactic": ""},
        {"technique_id": "T1016", "name": "System Network Configuration Discovery", "tactic": ""},
        {"technique_id": "T1049", "name": "System Network Connections Discovery", "tactic": ""},
    ],
}

POLYKG_RHADAMANTHYS_PROFILE = {
    "family": "Rhadamanthys",
    "description": "Rhadamanthys is an advanced C++ information-stealing malware first observed in late 2022. It operates as a Malware-as-a-Service (MaaS) platform with extensive data theft capabilities including cryptocurrency wallet credentials, browser data, email collections, and seed phrase recognition from images. The malware uses sophisticated obfuscation techniques including virtual machine obfuscation based on Quake III engine, custom embedded file systems, and multi-stage execution with custom XS module formats. It features a modular architecture with configurable C2 communications and supports multiple delivery methods including MSI installations.",
    "malware_type": ["Stealer", "Infostealer", "Trojan"],
    "actors": ["TA547", "Silent Ransom Group"],
    "origin_locations": [],
    "programming_languages": ["C++"],
    "systems_targeted": ["Windows"],
    "target_locations": ["Germany", "United States"],
    "verticals_targeted": ["Oil and Gas", "Legal Services", "Financial Services", "Cryptocurrency"],
    "related_malware": ["SmokeLoader"],
    "target_cves": [],
    "campaigns": ["Operation Endgame"],
    "updated": "2026-03-09T10:36:24.099600+00:00",
    "citations": "https://www.hivepro.com/wp-content/uploads/2023/01/Rhadamanthys-A-New-Evasive-Information-Stealer.pdf,https://medium.com/@anyrun/rhadamanthys-malware-overview-ebc12c1a874e,https://cyble.com/blog/rhadamanthys-new-stealer-spreading-through-google-ads/,https://www.huntress.com/threat-library/malware/rhadamanthys,https://thehackernews.com/2024/04/ta547-phishing-attack-hits-german-firms.html,https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/,https://assets.recordedfuture.com/insikt-report-pdfs/2024/mtp-2024-0926.pdf,https://www.zscaler.com/blogs/security-research/technical-analysis-rhadamanthys-obfuscation-techniques",
    "ttps": [
        {"technique_id": "T1598.002", "name": "Spearphishing Attachment", "tactic": "reconnaissance"},
        {"technique_id": "T1204", "name": "User Execution", "tactic": "execution"},
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
        {"technique_id": "T1055", "name": "Process Injection", "tactic": "defense-evasion"},
        {"technique_id": "T1218.011", "name": "Rundll32", "tactic": "defense-evasion"},
        {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
        {"technique_id": "T1497", "name": "Virtualization/Sandbox Evasion", "tactic": "defense-evasion"},
        {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "credential-access"},
        {"technique_id": "T1056", "name": "Input Capture", "tactic": "collection"},
        {"technique_id": "T1552.002", "name": "Credentials in Registry", "tactic": "credential-access"},
        {"technique_id": "T1082", "name": "System Information Discovery", "tactic": "discovery"},
        {"technique_id": "T1518", "name": "Software Discovery", "tactic": "discovery"},
        {"technique_id": "T1083", "name": "File and Directory Discovery", "tactic": "discovery"},
        {"technique_id": "T1087", "name": "Account Discovery", "tactic": "discovery"},
        {"technique_id": "T1005", "name": "Data from Local System", "tactic": "collection"},
        {"technique_id": "T1114", "name": "Email Collection", "tactic": "collection"},
        {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
        {"technique_id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "command-and-control"},
        {"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
    ],
}

POLYKG_BL00DY_PROFILE = {
    "family": "Bl00dy",
    "description": "Bl00dy is a ransomware family that emerged in May 2022, utilizing leaked LockBit ransomware builder source code. The malware encrypts victim files and appends the '.bl00dy' extension, then demands ransom payment through Telegram-based communications. Bl00dy primarily targets educational institutions by exploiting the PaperCut CVE-2023-27350 vulnerability for initial access, though it has also impacted healthcare, consumer goods, professional services, and IT sectors. The ransomware operators use legitimate remote management tools, Cobalt Strike beacons, DiceLoader, and TrueBot for command and control and post-exploitation activities.",
    "malware_type": ["Ransomware"],
    "actors": ["Bl00dy Ransomware Gang"],
    "origin_locations": [],
    "programming_languages": [],
    "systems_targeted": ["Windows"],
    "target_locations": ["United States", "United Kingdom"],
    "verticals_targeted": ["Education", "Healthcare", "Consumer Goods", "Professional Services", "IT & ITES"],
    "related_malware": ["LockBit"],
    "target_cves": ["CVE-2023-27350"],
    "campaigns": [],
    "updated": "2026-03-09T10:37:26.449202+00:00",
    "citations": "https://cyble.com/blog/bl00dy-new-ransomware-strain-active-in-the-wild/,https://www.bleepingcomputer.com/news/security/fbi-bl00dy-ransomware-targets-education-orgs-in-papercut-attacks/,https://www.techtarget.com/searchsecurity/news/366537554/Bl00dy-ransomware-threat-fbi-and-cisa-warn-of-papercut-risk-to-education,https://phishingtackle.com/blog/bl00dy-ransomware-threat-fbi-and-cisa-warn-of-papercut-risk-to-education",
    "ttps": [
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "impact"},
        {"technique_id": "T1083", "name": "File and Directory Discovery", "tactic": "discovery"},
        {"technique_id": "T1082", "name": "System Information Discovery", "tactic": "discovery"},
        {"technique_id": "T1057", "name": "Process Discovery", "tactic": "discovery"},
        {"technique_id": "T1518", "name": "Software Discovery", "tactic": "discovery"},
        {"technique_id": "T1569.002", "name": "Service Execution", "tactic": "execution"},
        {"technique_id": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control"},
        {"technique_id": "T1573.002", "name": "Asymmetric Cryptography", "tactic": "command-and-control"},
    ],
}

# Map of lowercase family name → profile dict (for the mock)
POLYKG_PROFILES = {
    "dtrack": POLYKG_DTRACK_PROFILE,
    "rhadamanthys": POLYKG_RHADAMANTHYS_PROFILE,
    "bl00dy": POLYKG_BL00DY_PROFILE,
}


class _MockPolykgResponse:
    """Minimal requests.Response stand-in."""

    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
        self.ok = 200 <= status_code < 400

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


def _mock_polykg_get(url, **kwargs):
    """Drop-in replacement for ``requests.get`` (health checks + attack patterns)."""
    if url.endswith("/v3/kg/profile"):
        return _MockPolykgResponse(None, status_code=204)
    if "/v3/kg/opencti/attack-patterns" in url:
        return _MockPolykgResponse(MOCK_ATTACK_PATTERNS_RESPONSE)
    return _MockPolykgResponse({"detail": "Not found"}, status_code=404)


def _mock_polykg_post(url, **kwargs):
    """Drop-in replacement for ``requests.post`` that returns canned profiles.

    The real endpoint is POST /v3/kg/profile with body {"family_name": "..."}.
    """
    if "/v3/kg/profile" in url:
        body = kwargs.get("json", {})
        name = (body.get("family_name") or "").strip().lower()
        profile = POLYKG_PROFILES.get(name)
        if profile is not None:
            return _MockPolykgResponse(profile)
        return _MockPolykgResponse({"detail": "Not found"}, status_code=404)

    return _MockPolykgResponse({"detail": "Not found"}, status_code=404)


@pytest.fixture()
def mock_polykg(monkeypatch):
    """Patch ``requests.get/post`` so ConnectorClient talks to a fake polykg."""
    import polyswarm_enrichment.client_api as _mod

    monkeypatch.setattr(_mod.requests, "get", _mock_polykg_get)
    monkeypatch.setattr(_mod.requests, "post", _mock_polykg_post)


@pytest.fixture()
def mock_polykg_attack_patterns(mock_polykg):
    """Alias — mock_polykg already patches client_api.requests for all polykg endpoints."""
    pass


def _scrub_authorization(request):
    """Remove the Authorization header from recorded VCR cassettes."""
    if "Authorization" in request.headers:
        request.headers["Authorization"] = "SCRUBBED"
    return request


@pytest.fixture()
def vcr_instance():
    """Pre-configured VCR instance shared across VCR-based tests."""
    cassette_dir = os.path.join(os.path.dirname(__file__), "cassettes")
    return vcr.VCR(
        cassette_library_dir=cassette_dir,
        record_mode="once",
        before_record_request=_scrub_authorization,
        decode_compressed_response=True,
    )
