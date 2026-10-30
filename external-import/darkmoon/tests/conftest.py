"""Shared pytest fixtures for the Darkmoon connector test suite."""

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

# Let test files import "connector"/"darkmoon_client" the same way main.py does.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from connector import ConnectorSettings  # noqa: E402


class FakeLogger:
    """Minimal stand-in for `ConnectorLogger` used throughout the test suite."""

    def info(self, *args: Any, **kwargs: Any) -> None:
        pass

    def debug(self, *args: Any, **kwargs: Any) -> None:
        pass

    def warning(self, *args: Any, **kwargs: Any) -> None:
        pass

    def error(self, *args: Any, **kwargs: Any) -> None:
        pass


@pytest.fixture
def fake_logger() -> FakeLogger:
    """A fresh `FakeLogger` for each test."""
    return FakeLogger()


def _settings_dict(export_path: str) -> dict[str, Any]:
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "name": "Darkmoon",
            "scope": "Vulnerability,Note,Report,Attack-Pattern",
            "log_level": "error",
            "duration_period": "PT5M",
        },
        "darkmoon": {
            "export_path": export_path,
            "tlp_level": "red",
            "import_since": "2026-01-01T00:00:00Z",
        },
    }


class TestConnectorSettings(ConnectorSettings):
    """Fake but valid `ConnectorSettings` for tests (bypasses env/config.yml)."""

    @classmethod
    def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
        return handler(_settings_dict("/tmp/darkmoon-data"))


@pytest.fixture
def connector_settings() -> TestConnectorSettings:
    """A fresh `TestConnectorSettings` for each test."""
    return TestConnectorSettings()


@pytest.fixture
def darkmoon_export(tmp_path: Path) -> Path:
    """Build a realistic Darkmoon OSS export directory on disk.

    Mirrors the layout and record shapes written by the Darkmoon engine:
    campaigns/<id>.json, vulnerabilities/<id>.json and targets.json.
    """
    (tmp_path / "campaigns").mkdir()
    (tmp_path / "vulnerabilities").mkdir()

    campaign_id = "camp_20260301_abcd1234"
    target_id = "tgt_abc123"

    (tmp_path / "targets.json").write_text(
        json.dumps(
            [
                {
                    "id": target_id,
                    "host": "app.example.com",
                    "ip": "10.0.0.5",
                    "os": "Linux",
                }
            ]
        ),
        encoding="utf-8",
    )

    (tmp_path / "campaigns" / f"{campaign_id}.json").write_text(
        json.dumps(
            {
                "id": campaign_id,
                "project_id": "proj_abc",
                "target_id": target_id,
                "session_id": "abcd1234",
                "date": "2026-03-01T10:00:00Z",
                "status": "completed",
                "methodology": "ISO 27001 / NIST SP 800-115 / MITRE ATT&CK",
                "overall_risk": "critical",
                "stats": {
                    "total_findings": 2,
                    "critical": 1,
                    "high": 1,
                    "exploited": 1,
                },
                "executive_summary": "Two impactful findings were confirmed.",
                "report_path": "/reports/pentest_report_app_example_com.md",
            }
        ),
        encoding="utf-8",
    )

    (tmp_path / "vulnerabilities" / f"{campaign_id}.json").write_text(
        json.dumps(
            [
                {
                    "id": "vuln_111111",
                    "campaign_id": campaign_id,
                    "project_id": "proj_abc",
                    "target_id": target_id,
                    "title": "SQL Injection in login form",
                    "severity": "critical",
                    "status": "exploited",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cve": None,
                    "category": "sql_injection",
                    "mitre_attack_id": "T1190",
                    "mitre_attack_name": "Exploit Public-Facing Application",
                    "iso27001_control": "A.8.28",
                    "description": "The login endpoint is vulnerable to SQL injection.",
                    "endpoint": "/api/login",
                    "discovered_by_agent": "php",
                    "discovered_at": "2026-03-01T10:12:00Z",
                    "evidence": {
                        "commands": [
                            "sqlmap -u http://app.example.com/api/login --data='user=test'"
                        ],
                        "raw_request": "POST /api/login HTTP/1.1\nHost: app.example.com",
                        "raw_response": "HTTP/1.1 200 OK",
                        "logs": ["[10:12:01] SQLi confirmed: extracted 3 tables"],
                        "explanation": "Unsanitized input reaches the SQL query.",
                    },
                    "remediation": "Use parameterized queries.",
                },
                {
                    "id": "vuln_222222",
                    "campaign_id": campaign_id,
                    "target_id": target_id,
                    "title": "Outdated nginx (CVE-2021-23017)",
                    "severity": "high",
                    "status": "confirmed",
                    "cvss_score": 8.1,
                    "cve": "CVE-2021-23017",
                    "category": "outdated_component CWE-787",
                    "description": "nginx resolver off-by-one heap write.",
                    "endpoint": "https://app.example.com",
                    "discovered_by_agent": "pentest",
                    "discovered_at": "2026-03-01T10:20:00Z",
                    "evidence": {"commands": [], "logs": []},
                    "remediation": "Upgrade nginx.",
                },
            ]
        ),
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture
def settings_for_export(darkmoon_export: Path):
    """A settings object whose export_path points at the fixture export dir."""
    export_path = str(darkmoon_export)

    class _Settings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(_settings_dict(export_path))

    return _Settings()
