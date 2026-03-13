#!/usr/bin/env python3
"""
Automated connector verification script for OpenCTI connectors.

Runs the code-level checks from the verification checklist against a connector directory.
Produces a structured report with PASS/FAIL/WARN status and suggested fixes.
Can auto-fix common issues with --fix flag and batch-verify all connectors with --batch.

Usage:
    python verify_connector.py <connector_path> [--fix] [--json]
    python verify_connector.py --batch [--json] [--type TYPE] [--fail-only]

Examples:
    python verify_connector.py internal-enrichment/team-cymru-scout
    python verify_connector.py external-import/alienvault --fix
    python verify_connector.py --batch --type internal-enrichment
    python verify_connector.py --batch --fail-only
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class Status(Enum):
    PASS = "✅ PASS"
    FAIL = "❌ FAIL"
    WARN = "⚠️  WARN"
    SKIP = "⏭️  SKIP"
    INFO = "ℹ️  INFO"
    FIXED = "🔧 FIXED"


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: Status
    message: str
    fix_suggestion: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    auto_fixable: bool = False


@dataclass
class FixResult:
    check_id: str
    file_path: str
    description: str
    replacements: int = 0


@dataclass
class VerificationReport:
    connector_path: str
    connector_type: str = ""
    results: list = field(default_factory=list)
    fixes_applied: list = field(default_factory=list)

    def add(self, result: CheckResult):
        self.results.append(result)

    def add_fix(self, fix: FixResult):
        self.fixes_applied.append(fix)

    def summary(self):
        counts = {}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts

    @property
    def pass_count(self):
        return self.summary().get(Status.PASS, 0) + self.summary().get(Status.FIXED, 0)

    @property
    def fail_count(self):
        return self.summary().get(Status.FAIL, 0)

    @property
    def warn_count(self):
        return self.summary().get(Status.WARN, 0)

    @property
    def total_checks(self):
        return len(self.results)

    @property
    def connector_name(self):
        return Path(self.connector_path).name

    def print_report(self):
        print(f"\n{'='*80}")
        print("  CONNECTOR VERIFICATION REPORT")
        print(f"  Path: {self.connector_path}")
        print(f"  Type: {self.connector_type}")
        print(f"{'='*80}\n")

        categories = {}
        for r in self.results:
            cat = r.check_id.split("-")[0] if "-" in r.check_id else "general"
            categories.setdefault(cat, []).append(r)

        for cat, results in categories.items():
            cat_title = {
                "file": "📁 File Structure",
                "code": "🔍 Code Quality",
                "stix": "🔗 STIX Compliance",
                "pattern": "📐 Pattern Compliance",
                "config": "⚙️  Configuration",
                "readme": "📖 Documentation",
            }.get(cat, f"📋 {cat.title()}")

            print(f"\n{cat_title}")
            print(f"{'-'*60}")
            for r in results:
                status_str = r.status.value
                print(f"  {status_str}  {r.title}")
                if r.message and r.status not in (Status.PASS, Status.FIXED):
                    print(f"         → {r.message}")
                if r.status == Status.FIXED:
                    print(f"         → {r.message}")
                if r.fix_suggestion and r.status == Status.FAIL:
                    print(f"         💡 {r.fix_suggestion}")
                if r.file_path:
                    loc = f"{r.file_path}"
                    if r.line_number:
                        loc += f":{r.line_number}"
                    print(f"         📍 {loc}")

        if self.fixes_applied:
            print("\n🔧 FIXES APPLIED")
            print(f"{'-'*60}")
            for fix in self.fixes_applied:
                print(f"  ✓ {fix.description}")
                print(f"    📍 {fix.file_path} ({fix.replacements} replacement(s))")

        print(f"\n{'='*80}")
        summary = self.summary()
        parts = []
        for status in [
            Status.PASS,
            Status.FIXED,
            Status.FAIL,
            Status.WARN,
            Status.SKIP,
            Status.INFO,
        ]:
            if status in summary:
                parts.append(f"{status.value}: {summary[status]}")
        print(f"  SUMMARY: {' | '.join(parts)}")
        total = len(self.results)
        passed = self.pass_count
        print(f"  Score: {passed}/{total} checks passed")
        print(f"{'='*80}\n")

    def to_json(self):
        return json.dumps(
            {
                "connector_path": self.connector_path,
                "connector_type": self.connector_type,
                "results": [
                    {
                        "check_id": r.check_id,
                        "title": r.title,
                        "status": r.status.name,
                        "message": r.message,
                        "fix_suggestion": r.fix_suggestion,
                        "file_path": r.file_path,
                        "line_number": r.line_number,
                        "auto_fixable": r.auto_fixable,
                    }
                    for r in self.results
                ],
                "fixes_applied": [
                    {
                        "check_id": f.check_id,
                        "file_path": f.file_path,
                        "description": f.description,
                        "replacements": f.replacements,
                    }
                    for f in self.fixes_applied
                ],
                "summary": {k.name: v for k, v in self.summary().items()},
            },
            indent=2,
        )


class ConnectorVerifier:
    def __init__(self, connector_path: str, apply_fix: bool = False):
        self.connector_path = Path(connector_path).resolve()
        self.apply_fix = apply_fix
        self.report = VerificationReport(connector_path=str(self.connector_path))
        self.src_path = self.connector_path / "src"
        self.metadata_path = self.connector_path / "__metadata__"

        # Detect connector type from path
        parent = self.connector_path.parent.name
        type_map = {
            "external-import": "EXTERNAL_IMPORT",
            "internal-enrichment": "INTERNAL_ENRICHMENT",
            "internal-export-file": "INTERNAL_EXPORT_FILE",
            "internal-import-file": "INTERNAL_IMPORT_FILE",
            "stream": "STREAM",
        }
        self.connector_type = type_map.get(parent, "UNKNOWN")
        self.report.connector_type = self.connector_type

        # Cache source files
        self._source_files = {}
        self._load_source_files()

    def _load_source_files(self):
        """Load all Python source files into memory for analysis."""
        if not self.src_path.exists():
            return
        for py_file in self.src_path.rglob("*.py"):
            rel_path = str(py_file.relative_to(self.connector_path))
            try:
                self._source_files[rel_path] = py_file.read_text(encoding="utf-8")
            except Exception:
                pass

    def _search_sources(self, pattern: str, regex: bool = False) -> list:
        """Search all source files for a pattern. Returns list of (file, line_num, line)."""
        matches = []
        for filepath, content in self._source_files.items():
            for i, line in enumerate(content.split("\n"), 1):
                if regex:
                    if re.search(pattern, line):
                        matches.append((filepath, i, line.strip()))
                else:
                    if pattern in line:
                        matches.append((filepath, i, line.strip()))
        return matches

    def _file_exists(self, *paths) -> bool:
        return (self.connector_path / Path(*paths)).exists()

    def _read_file(self, *paths) -> Optional[str]:
        fp = self.connector_path / Path(*paths)
        if fp.exists():
            try:
                return fp.read_text(encoding="utf-8")
            except Exception:
                return None
        return None

    def _write_file(self, content: str, *paths) -> bool:
        """Write content to a file relative to the connector path."""
        fp = self.connector_path / Path(*paths)
        try:
            fp.write_text(content, encoding="utf-8")
            return True
        except Exception:
            return False

    # =========================================================================
    # FIX METHODS
    # =========================================================================

    def fix_helper_log(self) -> Optional[FixResult]:
        """Replace helper.log_{level}(...) with helper.connector_logger.{level}(...)."""
        total_replacements = 0
        fixed_files = []

        for filepath, content in list(self._source_files.items()):
            original = content
            # Replace all variants: helper.log_info, log_error, log_warning, log_debug, log_warn
            content = re.sub(
                r"(\.helper\.)log_(info|error|warning|debug|warn)\(",
                r"\1connector_logger.\2(",
                content,
            )
            # Also handle standalone (non self.) patterns like helper.log_info
            content = re.sub(
                r"(?<!\.)(\bhelper\.)log_(info|error|warning|debug|warn)\(",
                r"\1connector_logger.\2(",
                content,
            )
            if content != original:
                count = original.count("helper.log_") - content.count("helper.log_")
                total_replacements += count
                abs_path = self.connector_path / filepath
                abs_path.write_text(content, encoding="utf-8")
                self._source_files[filepath] = content
                fixed_files.append(filepath)

        if total_replacements > 0:
            fix = FixResult(
                check_id="code-no-helper-log",
                file_path=", ".join(fixed_files),
                description="Replaced helper.log_{level}() with helper.connector_logger.{level}()",
                replacements=total_replacements,
            )
            self.report.add_fix(fix)
            return fix
        return None

    def fix_datetime_naive(self) -> Optional[FixResult]:
        """Replace datetime.now() and datetime.utcnow() with timezone-aware variants."""
        total_replacements = 0
        fixed_files = []

        for filepath, content in list(self._source_files.items()):
            original = content

            # Replace datetime.utcnow() → datetime.now(tz=timezone.utc)
            content = re.sub(
                r"datetime\.utcnow\(\)",
                "datetime.now(tz=timezone.utc)",
                content,
            )

            # Replace datetime.now() without args → datetime.now(tz=timezone.utc)
            # Be careful not to replace datetime.now(tz=...) or datetime.now(timezone...)
            content = re.sub(
                r"datetime\.now\(\s*\)(?!\.)",
                "datetime.now(tz=timezone.utc)",
                content,
            )

            if content != original:
                count = 0
                count += original.count("datetime.utcnow()") - content.count(
                    "datetime.utcnow()"
                )
                count += original.count("datetime.now()") - content.count(
                    "datetime.now()"
                )
                total_replacements += max(count, 1)

                # Ensure timezone import is present
                if "from datetime import" in content and "timezone" not in content:
                    content = re.sub(
                        r"(from datetime import .+)",
                        r"\1, timezone",
                        content,
                        count=1,
                    )
                elif "import datetime" in content and "from datetime" not in content:
                    # Uses datetime.datetime.now() style — change to
                    # datetime.datetime.now(tz=datetime.timezone.utc)
                    content = content.replace(
                        "datetime.now(tz=timezone.utc)",
                        "datetime.now(tz=datetime.timezone.utc)",
                    )

                abs_path = self.connector_path / filepath
                abs_path.write_text(content, encoding="utf-8")
                self._source_files[filepath] = content
                fixed_files.append(filepath)

        if total_replacements > 0:
            fix = FixResult(
                check_id="pattern-date-format",
                file_path=", ".join(fixed_files),
                description="Replaced naive datetime.now()/utcnow() with timezone-aware variants",
                replacements=total_replacements,
            )
            self.report.add_fix(fix)
            return fix
        return None

    def fix_connector_type_dockerfile(self) -> Optional[FixResult]:
        """Add ENV CONNECTOR_TYPE to Dockerfile if missing."""
        dockerfile = self._read_file("Dockerfile")
        if not dockerfile:
            return None

        if re.search(r"ENV\s+CONNECTOR_TYPE", dockerfile):
            return None

        # Insert ENV line after FROM line
        env_line = f"ENV CONNECTOR_TYPE={self.connector_type}\n"
        lines = dockerfile.split("\n")
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.strip().startswith("FROM "):
                insert_idx = i + 1
                break

        lines.insert(insert_idx, env_line.rstrip())
        new_content = "\n".join(lines)
        self._write_file(new_content, "Dockerfile")

        fix = FixResult(
            check_id="pattern-connector-type",
            file_path="Dockerfile",
            description=f"Added ENV CONNECTOR_TYPE={self.connector_type}",
            replacements=1,
        )
        self.report.add_fix(fix)
        return fix

    def fix_docker_compose_vars(self) -> Optional[FixResult]:
        """Add missing required env vars to docker-compose.yml."""
        compose = self._read_file("docker-compose.yml")
        if not compose:
            return None

        required_vars = {
            "CONNECTOR_ID": "CONNECTOR_ID=${CONNECTOR_ID}",
            "CONNECTOR_TYPE": f"CONNECTOR_TYPE={self.connector_type}",
        }

        additions = []
        for var, line in required_vars.items():
            if var not in compose:
                additions.append(line)

        if not additions:
            return None

        # Find the environment section and append
        lines = compose.split("\n")
        env_end_idx = None
        in_env = False
        indent = "      "
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "environment:" in stripped:
                in_env = True
                # Detect indent level
                if stripped.startswith("-"):
                    indent = " " * (len(line) - len(line.lstrip()) + 2)
                else:
                    indent = " " * (len(line) - len(line.lstrip()) + 2)
                continue
            if in_env:
                if stripped.startswith("- ") and "=" in stripped:
                    env_end_idx = i
                    # Use same indent as existing env vars
                    indent = " " * (len(line) - len(line.lstrip()))
                elif (
                    stripped
                    and not stripped.startswith("-")
                    and not stripped.startswith("#")
                ):
                    break

        if env_end_idx is not None:
            for j, addition in enumerate(additions):
                lines.insert(env_end_idx + 1 + j, f"{indent}- {addition}")

            new_content = "\n".join(lines)
            self._write_file(new_content, "docker-compose.yml")

            fix = FixResult(
                check_id="config-docker-compose",
                file_path="docker-compose.yml",
                description=f"Added missing env vars: {', '.join(r.split('=')[0] for r in additions)}",
                replacements=len(additions),
            )
            self.report.add_fix(fix)
            return fix
        return None

    def fix_readme_verified_table(self) -> Optional[FixResult]:
        """Add verified table to README.md if missing."""
        readme = self._read_file("README.md")
        if not readme:
            return None

        has_verified = "verified" in readme.lower() or "verification" in readme.lower()
        has_table = (
            "|" in readme
            and "---" in readme
            and ("Filigran Verified" in readme or "Partner" in readme)
        )

        if has_verified and has_table:
            return None

        today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

        verified_table = (
            "\n| Status | Date | Comment |\n"
            "|--------|------|---------|"
            f"\n| Filigran Verified | {today} | - |\n"
        )

        # Insert after the first heading
        lines = readme.split("\n")
        insert_idx = 1
        for i, line in enumerate(lines):
            if line.startswith("# "):
                insert_idx = i + 1
                # Skip any blank lines after the heading
                while insert_idx < len(lines) and not lines[insert_idx].strip():
                    insert_idx += 1
                break

        lines.insert(insert_idx, verified_table)
        new_content = "\n".join(lines)
        self._write_file(new_content, "README.md")

        fix = FixResult(
            check_id="readme-verified-table",
            file_path="README.md",
            description=f"Added verification status table with date {today}",
            replacements=1,
        )
        self.report.add_fix(fix)
        return fix

    def fix_manifest_verified_date(self) -> Optional[FixResult]:
        """Set verified=true and last_verified_date in connector_manifest.json."""
        manifest = self._read_file("__metadata__", "connector_manifest.json")
        if not manifest:
            return None

        try:
            mdata = json.loads(manifest)
        except json.JSONDecodeError:
            return None

        changed = False
        today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

        if not mdata.get("verified"):
            mdata["verified"] = True
            changed = True

        if mdata.get("last_verified_date") != today:
            mdata["last_verified_date"] = today
            changed = True

        if not changed:
            return None

        new_content = json.dumps(mdata, indent=2, ensure_ascii=False) + "\n"
        self._write_file(new_content, "__metadata__", "connector_manifest.json")

        fix = FixResult(
            check_id="config-manifest-verified",
            file_path="__metadata__/connector_manifest.json",
            description=f"Set verified=true, last_verified_date={today}",
            replacements=1,
        )
        self.report.add_fix(fix)
        return fix

    def apply_all_fixes(self):
        """Apply all available auto-fixes. Run BEFORE checks to update status."""
        fixes = []
        fixes.append(self.fix_helper_log())
        fixes.append(self.fix_datetime_naive())
        fixes.append(self.fix_connector_type_dockerfile())
        fixes.append(self.fix_docker_compose_vars())
        fixes.append(self.fix_readme_verified_table())
        fixes.append(self.fix_manifest_verified_date())
        # Reload source files after fixes
        self._source_files = {}
        self._load_source_files()
        return [f for f in fixes if f is not None]

    # =========================================================================
    # FILE STRUCTURE CHECKS
    # =========================================================================

    def check_file_structure(self):
        """Check that all required files exist."""
        required_files = {
            "Dockerfile": "Dockerfile",
            "docker-compose.yml": "docker-compose.yml",
            ".env.sample": ".env.sample",
            "README.md": "README.md",
            "src/requirements.txt": "src/requirements.txt",
            "src/main.py": "src/main.py",
            "__metadata__/connector_manifest.json": "__metadata__/connector_manifest.json",
            "__metadata__/logo.png": "__metadata__/logo.png",
        }

        for label, path in required_files.items():
            exists = self._file_exists(path)
            self.report.add(
                CheckResult(
                    check_id=f"file-{label.replace('/', '-').replace('.', '-')}",
                    title=f"File exists: {label}",
                    status=Status.PASS if exists else Status.FAIL,
                    message="" if exists else f"Missing required file: {path}",
                    fix_suggestion=f"Create {path} following the template structure",
                )
            )

        # Optional but recommended
        optional_files = {
            "__metadata__/connector_config_schema.json": "Config schema (auto-generated)",
            "__metadata__/CONNECTOR_CONFIG_DOC.md": "Config documentation",
            "entrypoint.sh": "Container entrypoint (optional if CMD used)",
        }
        for path, desc in optional_files.items():
            exists = self._file_exists(path)
            self.report.add(
                CheckResult(
                    check_id=f"file-optional-{path.replace('/', '-').replace('.', '-')}",
                    title=f"Optional file: {desc}",
                    status=Status.PASS if exists else Status.INFO,
                    message="" if exists else f"Optional file missing: {path}",
                )
            )

    # =========================================================================
    # DEPRECATED PATTERNS (must NOT be present)
    # =========================================================================

    def check_no_confidence_level(self):
        matches = self._search_sources("CONFIDENCE_LEVEL")
        # Exclude settings files that legitimately define it as a config field
        real_matches = [m for m in matches if "settings" not in m[0]]
        self.report.add(
            CheckResult(
                check_id="code-no-confidence-level",
                title="No use of CONFIDENCE_LEVEL variable",
                status=Status.PASS if not real_matches else Status.FAIL,
                message=(
                    ""
                    if not real_matches
                    else f"Found {len(real_matches)} usage(s) of CONFIDENCE_LEVEL"
                ),
                fix_suggestion="Remove CONFIDENCE_LEVEL usage; use max_confidence_level in manifest instead",
                file_path=real_matches[0][0] if real_matches else None,
                line_number=real_matches[0][1] if real_matches else None,
                auto_fixable=False,
            )
        )

    def check_no_helper_api(self):
        matches = self._search_sources(r"helper\.api[^_]", regex=True)
        # Filter out legitimate uses like helper.api.work (which is acceptable)
        # We want to flag direct API calls that bypass the helper
        flagged = [m for m in matches if "helper.api.work" not in m[2]]
        self.report.add(
            CheckResult(
                check_id="code-no-helper-api",
                title="No direct use of helper.api (except helper.api.work)",
                status=Status.PASS if not flagged else Status.WARN,
                message=(
                    ""
                    if not flagged
                    else f"Found {len(flagged)} direct helper.api usage(s)"
                ),
                fix_suggestion="Use helper methods instead of direct API access where possible",
                file_path=flagged[0][0] if flagged else None,
                line_number=flagged[0][1] if flagged else None,
            )
        )

    def check_no_update_existing_data(self):
        matches = self._search_sources("UPDATE_EXISTING_DATA")
        self.report.add(
            CheckResult(
                check_id="code-no-update-existing-data",
                title="No use of UPDATE_EXISTING_DATA variable",
                status=Status.PASS if not matches else Status.FAIL,
                message=(
                    ""
                    if not matches
                    else f"Found {len(matches)} usage(s) of UPDATE_EXISTING_DATA"
                ),
                fix_suggestion="Remove UPDATE_EXISTING_DATA; use the 'update' parameter in send_stix2_bundle instead",
                file_path=matches[0][0] if matches else None,
                line_number=matches[0][1] if matches else None,
                auto_fixable=True,
            )
        )

    def check_no_helper_log(self):
        matches = self._search_sources(r"helper\.log_", regex=True)
        self.report.add(
            CheckResult(
                check_id="code-no-helper-log",
                title="No use of deprecated helper.log_{level}()",
                status=Status.PASS if not matches else Status.FAIL,
                message=(
                    ""
                    if not matches
                    else f"Found {len(matches)} usage(s); use helper.connector_logger instead"
                ),
                fix_suggestion="Replace helper.log_info/warning/error with helper.connector_logger.info/warning/error",
                file_path=matches[0][0] if matches else None,
                line_number=matches[0][1] if matches else None,
                auto_fixable=True,
            )
        )

    def check_no_x_opencti_report_status(self):
        matches = self._search_sources("x_opencti_report_status")
        self.report.add(
            CheckResult(
                check_id="code-no-report-status",
                title="No use of x_opencti_report_status",
                status=Status.PASS if not matches else Status.FAIL,
                message=(
                    ""
                    if not matches
                    else f"Found {len(matches)} usage(s) of x_opencti_report_status"
                ),
                fix_suggestion="Remove x_opencti_report_status; report status should not be set by connectors",
                file_path=matches[0][0] if matches else None,
                line_number=matches[0][1] if matches else None,
            )
        )

    def check_no_interval_config(self):
        """Check that 'interval' is not used (duration_period should be used instead)."""
        # Only relevant for external-import connectors
        if self.connector_type != "EXTERNAL_IMPORT":
            self.report.add(
                CheckResult(
                    check_id="code-no-interval",
                    title="No use of interval (duration_period instead)",
                    status=Status.SKIP,
                    message="Not applicable for this connector type",
                )
            )
            return

        matches = self._search_sources(r"\binterval\b", regex=True)
        # Filter out comments and unrelated uses
        real_matches = [
            m
            for m in matches
            if not m[2].strip().startswith("#") and "duration_period" not in m[2]
        ]
        self.report.add(
            CheckResult(
                check_id="code-no-interval",
                title="No use of interval (duration_period instead)",
                status=Status.PASS if not real_matches else Status.FAIL,
                message=(
                    ""
                    if not real_matches
                    else f"Found {len(real_matches)} interval usage(s); use duration_period"
                ),
                fix_suggestion="Replace 'interval' configuration with 'duration_period' (ISO 8601 duration format)",
                file_path=real_matches[0][0] if real_matches else None,
                line_number=real_matches[0][1] if real_matches else None,
                auto_fixable=True,
            )
        )

    # =========================================================================
    # STIX COMPLIANCE CHECKS
    # =========================================================================

    def check_deterministic_ids(self):
        """Check that STIX objects use deterministic IDs (generate_id or SDK models)."""
        has_generate_id = bool(self._search_sources("generate_id"))
        has_sdk_models = bool(self._search_sources("from connectors_sdk"))

        # Filter to actual STIX SDO/SRO creations (not utilities)
        sdo_types = [
            "Identity",
            "Report",
            "Indicator",
            "Malware",
            "ThreatActor",
            "Campaign",
            "IntrusionSet",
            "Vulnerability",
            "AttackPattern",
            "Tool",
            "Note",
            "Opinion",
            "ObservedData",
            "Grouping",
            "Location",
            "Infrastructure",
        ]
        sdo_pattern = "|".join(sdo_types)
        sdo_creations = self._search_sources(rf"stix2\.({sdo_pattern})\(", regex=True)

        if not sdo_creations and not has_sdk_models:
            self.report.add(
                CheckResult(
                    check_id="stix-deterministic-ids",
                    title="Use deterministic STIX IDs (generate_id / SDK models)",
                    status=Status.INFO,
                    message="No direct stix2 SDO creation found",
                )
            )
        elif has_generate_id or has_sdk_models:
            self.report.add(
                CheckResult(
                    check_id="stix-deterministic-ids",
                    title="Use deterministic STIX IDs (generate_id / SDK models)",
                    status=Status.PASS,
                    message="Uses generate_id() or connectors-sdk models",
                )
            )
        else:
            self.report.add(
                CheckResult(
                    check_id="stix-deterministic-ids",
                    title="Use deterministic STIX IDs (generate_id / SDK models)",
                    status=Status.FAIL,
                    message=f"Found {len(sdo_creations)} stix2 object creation(s) without generate_id",
                    fix_suggestion="Use pycti.<Entity>.generate_id() or connectors-sdk models for deterministic IDs",
                    file_path=sdo_creations[0][0] if sdo_creations else None,
                    line_number=sdo_creations[0][1] if sdo_creations else None,
                )
            )

    def check_external_references(self):
        matches = self._search_sources("external_reference")
        ext_ref_import = self._search_sources("ExternalReference")
        has_refs = bool(matches) or bool(ext_ref_import)
        self.report.add(
            CheckResult(
                check_id="stix-external-refs",
                title="Use external references to source portal",
                status=Status.PASS if has_refs else Status.WARN,
                message=(
                    ""
                    if has_refs
                    else "No external references found; consider adding source portal links"
                ),
                fix_suggestion="Add ExternalReference with source_name and URL to the source portal",
            )
        )

    def check_markings_usage(self):
        """Check that markings/TLP are handled."""
        has_tlp = bool(self._search_sources("TLP"))
        has_marking = bool(self._search_sources("marking"))
        has_max_tlp = bool(self._search_sources("max_tlp"))
        has_check_tlp = bool(self._search_sources("check_max_tlp"))

        if has_check_tlp and has_max_tlp:
            status = Status.PASS
            msg = "TLP markings are checked with max_tlp configuration"
        elif has_tlp or has_marking:
            status = Status.WARN
            msg = "Markings referenced but check_max_tlp not found"
        else:
            status = Status.FAIL
            msg = "No TLP/marking handling found"

        self.report.add(
            CheckResult(
                check_id="stix-markings",
                title="Use Marking (TLP) on entities with max_tlp check",
                status=status,
                message=msg,
                fix_suggestion="Implement extract_and_check_markings() with helper.check_max_tlp()",
            )
        )

    def check_author_reference(self):
        """Check that author identity is created and referenced on entities."""
        has_identity = bool(self._search_sources("Identity"))
        has_created_by = bool(self._search_sources("created_by_ref"))
        has_org_author = bool(self._search_sources("OrganizationAuthor"))

        if has_org_author or (has_identity and has_created_by):
            status = Status.PASS
            msg = "Author identity created and referenced via created_by_ref"
        elif has_identity:
            status = Status.WARN
            msg = "Identity created but created_by_ref not found on all entities"
        else:
            status = Status.FAIL
            msg = "No author identity found"

        self.report.add(
            CheckResult(
                check_id="stix-author",
                title="Author is well referenced on entities",
                status=status,
                message=msg,
                fix_suggestion="Create an OrganizationAuthor and set created_by_ref on all STIX objects",
            )
        )

    def check_cleanup_bundle(self):
        """Check use of cleanup_inconsistent_bundle (mainly for external-import)."""
        matches = self._search_sources("cleanup_inconsistent_bundle")
        if self.connector_type == "EXTERNAL_IMPORT":
            self.report.add(
                CheckResult(
                    check_id="stix-cleanup-bundle",
                    title="Use cleanup_inconsistent_bundle",
                    status=Status.PASS if matches else Status.FAIL,
                    message=(
                        ""
                        if matches
                        else "Missing cleanup_inconsistent_bundle=True in send_stix2_bundle"
                    ),
                    fix_suggestion="Add cleanup_inconsistent_bundle=True to send_stix2_bundle() calls",
                )
            )
        else:
            self.report.add(
                CheckResult(
                    check_id="stix-cleanup-bundle",
                    title="Use cleanup_inconsistent_bundle",
                    status=Status.PASS if matches else Status.INFO,
                    message=(
                        "cleanup_inconsistent_bundle used"
                        if matches
                        else "Not used (optional for this connector type)"
                    ),
                )
            )

    # =========================================================================
    # PATTERN COMPLIANCE CHECKS
    # =========================================================================

    def check_traceback_in_main(self):
        """Check main.py uses traceback pattern."""
        main_content = self._read_file("src", "main.py")
        if not main_content:
            self.report.add(
                CheckResult(
                    check_id="pattern-traceback",
                    title="Use Traceback in main.py",
                    status=Status.FAIL,
                    message="main.py not found",
                )
            )
            return

        has_traceback_import = "import traceback" in main_content
        has_traceback_call = "traceback.print_exc()" in main_content
        has_exit = "exit(1)" in main_content
        has_except = "except Exception" in main_content

        all_good = all([has_traceback_import, has_traceback_call, has_exit, has_except])
        missing = []
        if not has_traceback_import:
            missing.append("import traceback")
        if not has_traceback_call:
            missing.append("traceback.print_exc()")
        if not has_exit:
            missing.append("exit(1)")
        if not has_except:
            missing.append("except Exception")

        self.report.add(
            CheckResult(
                check_id="pattern-traceback",
                title="Use Traceback in main.py",
                status=Status.PASS if all_good else Status.FAIL,
                message="" if all_good else f"Missing: {', '.join(missing)}",
                fix_suggestion="Add try/except with traceback.print_exc() and exit(1) in main.py",
                file_path="src/main.py",
                auto_fixable=True,
            )
        )

    def check_error_handling(self):
        """Check for clear error handling in connector."""
        connector_files = [
            f
            for f in self._source_files
            if "connector" in f.lower() and f.endswith(".py") and "test" not in f
        ]

        if not connector_files:
            self.report.add(
                CheckResult(
                    check_id="pattern-error-handling",
                    title="Use clear Error Handling",
                    status=Status.WARN,
                    message="No connector.py file found",
                )
            )
            return

        has_try_except = False
        has_error_log = False
        for f in connector_files:
            content = self._source_files[f]
            if "try:" in content and "except" in content:
                has_try_except = True
            if "connector_logger.error" in content or "log_error" in content:
                has_error_log = True

        self.report.add(
            CheckResult(
                check_id="pattern-error-handling",
                title="Use clear Error Handling",
                status=(
                    Status.PASS if (has_try_except and has_error_log) else Status.WARN
                ),
                message=(
                    ""
                    if (has_try_except and has_error_log)
                    else "Ensure try/except with proper error logging in process_message"
                ),
            )
        )

    def check_connector_type_in_dockerfile(self):
        """Check CONNECTOR_TYPE is defined in Dockerfile or application."""
        dockerfile = self._read_file("Dockerfile")
        if not dockerfile:
            self.report.add(
                CheckResult(
                    check_id="pattern-connector-type",
                    title="Define CONNECTOR_TYPE in application",
                    status=Status.FAIL,
                    message="Dockerfile not found",
                )
            )
            return

        has_env = bool(re.search(r"ENV\s+CONNECTOR_TYPE", dockerfile))
        # Also check if settings define it via SDK base class
        has_sdk_type = (
            bool(self._search_sources("BaseInternalEnrichmentConnectorConfig"))
            or bool(self._search_sources("BaseExternalImportConnectorConfig"))
            or bool(self._search_sources("BaseStreamConnectorConfig"))
        )

        if has_env or has_sdk_type:
            status = Status.PASS
            msg = ""
        else:
            status = Status.FAIL
            msg = "CONNECTOR_TYPE not set in Dockerfile ENV or SDK base settings"

        self.report.add(
            CheckResult(
                check_id="pattern-connector-type",
                title="Define CONNECTOR_TYPE in application",
                status=status,
                message=msg,
                fix_suggestion=f"Add 'ENV CONNECTOR_TYPE={self.connector_type}' to Dockerfile",
                auto_fixable=True,
            )
        )

    def check_absolute_imports(self):
        """Check that absolute imports are used (not relative)."""
        relative_imports = self._search_sources(
            r"^\s*from\s+\.\w+\s+import", regex=True
        )
        # Relative imports within the same package are OK
        # We mainly flag relative imports in main.py or cross-package
        main_relatives = [m for m in relative_imports if "main.py" in m[0]]

        self.report.add(
            CheckResult(
                check_id="pattern-absolute-imports",
                title="Use absolute imports",
                status=Status.PASS if not main_relatives else Status.FAIL,
                message=(
                    "" if not main_relatives else "Found relative imports in main.py"
                ),
                fix_suggestion="Use absolute imports (e.g., 'from connector.settings import ...' not 'from .settings import ...')",
                file_path=main_relatives[0][0] if main_relatives else None,
                line_number=main_relatives[0][1] if main_relatives else None,
            )
        )

    def check_helper_listen(self):
        """Check that the appropriate listener is used."""
        has_listen = bool(self._search_sources("helper.listen("))
        has_schedule = bool(self._search_sources("schedule_process"))
        has_listen_stream = bool(self._search_sources("listen_stream"))

        if self.connector_type == "INTERNAL_ENRICHMENT":
            self.report.add(
                CheckResult(
                    check_id="pattern-helper-listen",
                    title="Ensure helper.listen is used",
                    status=Status.PASS if has_listen else Status.FAIL,
                    message=(
                        ""
                        if has_listen
                        else "helper.listen() not found; required for enrichment connectors"
                    ),
                    fix_suggestion="Add self.helper.listen(message_callback=self.process_message) in run()/start()",
                )
            )
        elif self.connector_type == "EXTERNAL_IMPORT":
            self.report.add(
                CheckResult(
                    check_id="pattern-helper-listen",
                    title="Ensure helper.schedule_process is used",
                    status=Status.PASS if has_schedule else Status.FAIL,
                    message=(
                        ""
                        if has_schedule
                        else "schedule_process not found; required for external-import connectors"
                    ),
                    fix_suggestion="Use helper.schedule_process(message_callback=..., duration_period=...)",
                )
            )
        elif self.connector_type == "STREAM":
            self.report.add(
                CheckResult(
                    check_id="pattern-helper-listen",
                    title="Ensure helper.listen_stream is used",
                    status=Status.PASS if has_listen_stream else Status.FAIL,
                    message=(
                        ""
                        if has_listen_stream
                        else "listen_stream not found; required for stream connectors"
                    ),
                    fix_suggestion="Use helper.listen_stream(message_callback=self.process_message)",
                )
            )
        else:
            self.report.add(
                CheckResult(
                    check_id="pattern-helper-listen",
                    title="Ensure appropriate listener is used",
                    status=Status.INFO,
                    message="Listener check skipped for this connector type",
                )
            )

    def check_playbook_compatible(self):
        """Check playbook compatibility for enrichment connectors."""
        if self.connector_type != "INTERNAL_ENRICHMENT":
            self.report.add(
                CheckResult(
                    check_id="pattern-playbook",
                    title="Ensure playbook compliant",
                    status=Status.SKIP,
                    message="Only applicable for internal-enrichment connectors",
                )
            )
            return

        main_content = self._read_file("src", "main.py") or ""
        has_playbook = "playbook_compatible" in main_content

        self.report.add(
            CheckResult(
                check_id="pattern-playbook",
                title="Ensure playbook compliant",
                status=Status.PASS if has_playbook else Status.WARN,
                message=(
                    ""
                    if has_playbook
                    else "playbook_compatible not set in OpenCTIConnectorHelper init"
                ),
                fix_suggestion="Add playbook_compatible=True in OpenCTIConnectorHelper() constructor",
                file_path="src/main.py",
            )
        )

    def check_scope_handling(self):
        """For enrichment: ensure out-of-scope entities return original bundle."""
        if self.connector_type != "INTERNAL_ENRICHMENT":
            self.report.add(
                CheckResult(
                    check_id="pattern-scope-return",
                    title="Return original bundle if not in scope",
                    status=Status.SKIP,
                    message="Only applicable for internal-enrichment connectors",
                )
            )
            return

        # Look for scope checking pattern
        has_scope_check = bool(self._search_sources("entity_type")) or bool(
            self._search_sources("observable_type")
        )

        self.report.add(
            CheckResult(
                check_id="pattern-scope-return",
                title="Return original bundle if not in scope",
                status=Status.PASS if has_scope_check else Status.WARN,
                message=(
                    ""
                    if has_scope_check
                    else "No entity type/scope check found in process_message"
                ),
                fix_suggestion="Check observable type against connector scope and return early if not supported",
            )
        )

    def check_base_settings_sdk(self):
        """Check that connector uses BaseConnectorSettings from connectors-sdk."""
        has_base_settings = bool(self._search_sources("BaseConnectorSettings"))

        self.report.add(
            CheckResult(
                check_id="pattern-base-settings",
                title="Implement Base Settings from connectors SDK",
                status=Status.PASS if has_base_settings else Status.FAIL,
                message=(
                    ""
                    if has_base_settings
                    else "Not using BaseConnectorSettings from connectors-sdk"
                ),
                fix_suggestion="Create settings.py with BaseConnectorSettings, BaseConfigModel from connectors_sdk",
                auto_fixable=False,
            )
        )

    def check_date_formatting(self):
        """Check for proper date formatting with timezone awareness."""
        # Look for naive datetime usage
        naive_dates = self._search_sources(r"datetime\.now\(\s*\)", regex=True)
        utcnow = self._search_sources(r"datetime\.utcnow\(\s*\)", regex=True)

        issues = naive_dates + utcnow
        self.report.add(
            CheckResult(
                check_id="pattern-date-format",
                title="Use proper date formatting AND time zone",
                status=Status.PASS if not issues else Status.WARN,
                message=(
                    ""
                    if not issues
                    else f"Found {len(issues)} naive/utcnow datetime usage(s); use timezone-aware datetimes"
                ),
                fix_suggestion="Use datetime.now(tz=datetime.timezone.utc) instead of datetime.now() or datetime.utcnow()",
                file_path=issues[0][0] if issues else None,
                line_number=issues[0][1] if issues else None,
                auto_fixable=True,
            )
        )

    def check_backpressure(self):
        """Check auto backpressure is implemented (duration_period for external-import)."""
        if self.connector_type != "EXTERNAL_IMPORT":
            self.report.add(
                CheckResult(
                    check_id="pattern-backpressure",
                    title="Ensure auto backpressure is implemented",
                    status=Status.SKIP,
                    message="Duration period backpressure only applies to external-import connectors",
                )
            )
            return

        has_duration = bool(self._search_sources("duration_period"))
        self.report.add(
            CheckResult(
                check_id="pattern-backpressure",
                title="Ensure auto backpressure is implemented",
                status=Status.PASS if has_duration else Status.FAIL,
                message=(
                    ""
                    if has_duration
                    else "No duration_period found; required for scheduling"
                ),
                fix_suggestion="Add duration_period config and use in helper.schedule_process()",
            )
        )

    def check_work_management(self):
        """Check work initiation and completion for external-import connectors."""
        if self.connector_type != "EXTERNAL_IMPORT":
            # For enrichment, work is managed by helper internally
            self.report.add(
                CheckResult(
                    check_id="pattern-work-mgmt",
                    title="Work management (initiate/close)",
                    status=Status.SKIP,
                    message="Work is managed internally by helper for this connector type",
                )
            )
            return

        has_initiate = bool(self._search_sources("initiate_work"))
        has_to_processed = bool(self._search_sources("to_processed"))
        has_send_bundle = bool(self._search_sources("send_stix2_bundle"))

        issues = []
        if not has_initiate:
            issues.append("Missing initiate_work_id")
        if not has_to_processed:
            issues.append("Missing work.to_processed (work not closed)")
        if not has_send_bundle:
            issues.append("Missing send_stix2_bundle")

        self.report.add(
            CheckResult(
                check_id="pattern-work-mgmt",
                title="Work management (initiate/close)",
                status=Status.PASS if not issues else Status.FAIL,
                message="" if not issues else "; ".join(issues),
                fix_suggestion="Ensure work_id = helper.api.work.initiate_work(...), send_stix2_bundle(work_id=...), api.work.to_processed(work_id, ...)",
            )
        )

    # =========================================================================
    # CONFIG / DOCKERFILE CHECKS
    # =========================================================================

    def check_dockerfile_pattern(self):
        """Verify Dockerfile follows the standard pattern."""
        dockerfile = self._read_file("Dockerfile")
        if not dockerfile:
            return

        issues = []
        if (
            "python:3.12-alpine" not in dockerfile
            and "python:3.11-alpine" not in dockerfile
        ):
            issues.append("Should use python:3.12-alpine (or 3.11-alpine if required)")
        if "CONNECTOR_TYPE" not in dockerfile:
            # Already covered by connector-type check, but note if CMD is used directly
            pass
        if "CMD" not in dockerfile and "ENTRYPOINT" not in dockerfile:
            issues.append("No CMD or ENTRYPOINT defined")
        if "libmagic" not in dockerfile:
            issues.append("Missing libmagic in apk install (needed by pycti)")

        self.report.add(
            CheckResult(
                check_id="config-dockerfile",
                title="Dockerfile follows standard pattern",
                status=Status.PASS if not issues else Status.WARN,
                message="" if not issues else "; ".join(issues),
            )
        )

    def check_docker_compose(self):
        """Verify docker-compose.yml has required env vars."""
        compose = self._read_file("docker-compose.yml")
        if not compose:
            return

        required_vars = ["OPENCTI_URL", "OPENCTI_TOKEN", "CONNECTOR_ID"]
        missing = [v for v in required_vars if v not in compose]

        self.report.add(
            CheckResult(
                check_id="config-docker-compose",
                title="docker-compose.yml has required environment variables",
                status=Status.PASS if not missing else Status.FAIL,
                message=(
                    "" if not missing else f"Missing env vars: {', '.join(missing)}"
                ),
                fix_suggestion="Add missing environment variables to docker-compose.yml",
                file_path="docker-compose.yml",
                auto_fixable=True,
            )
        )

    def check_env_sample(self):
        """Verify .env.sample has all required variables."""
        env_sample = self._read_file(".env.sample")
        if not env_sample:
            return

        required_vars = [
            "OPENCTI_URL",
            "OPENCTI_TOKEN",
            "CONNECTOR_ID",
            "CONNECTOR_TYPE",
        ]
        missing = [v for v in required_vars if v not in env_sample]

        self.report.add(
            CheckResult(
                check_id="config-env-sample",
                title=".env.sample has required variables",
                status=Status.PASS if not missing else Status.FAIL,
                message="" if not missing else f"Missing vars: {', '.join(missing)}",
                file_path=".env.sample",
            )
        )

    def check_manifest(self):
        """Check connector_manifest.json for required fields."""
        manifest = self._read_file("__metadata__", "connector_manifest.json")
        if not manifest:
            self.report.add(
                CheckResult(
                    check_id="config-manifest",
                    title="connector_manifest.json is complete",
                    status=Status.FAIL,
                    message="connector_manifest.json not found",
                )
            )
            return

        try:
            mdata = json.loads(manifest)
        except json.JSONDecodeError as e:
            self.report.add(
                CheckResult(
                    check_id="config-manifest",
                    title="connector_manifest.json is valid JSON",
                    status=Status.FAIL,
                    message=f"Invalid JSON: {e}",
                )
            )
            return

        required_fields = [
            "title",
            "slug",
            "description",
            "short_description",
            "logo",
            "use_cases",
            "verified",
            "manager_supported",
            "container_type",
            "container_image",
            "source_code",
        ]
        missing = [f for f in required_fields if f not in mdata]
        issues = []

        if mdata.get("verified") is True and "last_verified_date" not in mdata:
            issues.append("verified=true but last_verified_date not set")

        if mdata.get("container_type") != self.connector_type:
            issues.append(
                f"container_type '{mdata.get('container_type')}' doesn't match expected '{self.connector_type}'"
            )

        self.report.add(
            CheckResult(
                check_id="config-manifest",
                title="connector_manifest.json is complete",
                status=Status.PASS if (not missing and not issues) else Status.FAIL,
                message=(
                    ""
                    if (not missing and not issues)
                    else f"Missing fields: {missing}; Issues: {issues}"
                ),
                file_path="__metadata__/connector_manifest.json",
            )
        )

    def check_requirements(self):
        """Check requirements.txt for expected dependencies."""
        reqs = self._read_file("src", "requirements.txt")
        if not reqs:
            return

        has_pycti = "pycti" in reqs
        has_sdk = "connectors-sdk" in reqs

        issues = []
        if not has_pycti:
            issues.append("Missing pycti dependency")
        if not has_sdk:
            issues.append("Missing connectors-sdk dependency")

        self.report.add(
            CheckResult(
                check_id="config-requirements",
                title="requirements.txt has expected dependencies",
                status=Status.PASS if not issues else Status.WARN,
                message="" if not issues else "; ".join(issues),
                file_path="src/requirements.txt",
            )
        )

    # =========================================================================
    # README CHECKS
    # =========================================================================

    def check_readme_completeness(self):
        """Check README.md for required sections."""
        readme = self._read_file("README.md")
        if not readme:
            self.report.add(
                CheckResult(
                    check_id="readme-complete",
                    title="README.md is complete",
                    status=Status.FAIL,
                    message="README.md not found",
                )
            )
            return

        expected_sections = ["Installation", "Configuration", "Description"]
        readme_lower = readme.lower()
        missing = [s for s in expected_sections if s.lower() not in readme_lower]

        self.report.add(
            CheckResult(
                check_id="readme-complete",
                title="README.md has expected sections",
                status=Status.PASS if not missing else Status.WARN,
                message=(
                    "" if not missing else f"Missing sections: {', '.join(missing)}"
                ),
                fix_suggestion="Add missing sections to README.md",
            )
        )

    def check_readme_verified_table(self):
        """Check README has verification/compatibility table."""
        readme = self._read_file("README.md")
        if not readme:
            return

        has_verified = "verified" in readme.lower() or "verification" in readme.lower()
        has_table = "|" in readme and "---" in readme

        self.report.add(
            CheckResult(
                check_id="readme-verified-table",
                title="README has Verified/compatibility table",
                status=Status.PASS if (has_verified and has_table) else Status.WARN,
                message=(
                    ""
                    if (has_verified and has_table)
                    else "No verification table found in README"
                ),
                fix_suggestion="Add a verification status table with date and OpenCTI version",
                auto_fixable=True,
            )
        )

    # =========================================================================
    # TEMPLATE COMPLIANCE
    # =========================================================================

    def check_template_structure(self):
        """Verify connector follows the template directory structure."""
        expected_dirs = ["src", "__metadata__"]
        missing_dirs = [
            d for d in expected_dirs if not (self.connector_path / d).is_dir()
        ]

        # Check for the connector package inside src/
        src_packages = (
            [
                d
                for d in (self.src_path).iterdir()
                if d.is_dir()
                and not d.name.startswith("__")
                and not d.name.startswith(".")
            ]
            if self.src_path.exists()
            else []
        )

        self.report.add(
            CheckResult(
                check_id="pattern-template-structure",
                title="Follows template directory structure",
                status=(
                    Status.PASS if (not missing_dirs and src_packages) else Status.FAIL
                ),
                message=(
                    ""
                    if (not missing_dirs and src_packages)
                    else f"Missing dirs: {missing_dirs}; connector package: {bool(src_packages)}"
                ),
            )
        )

    def check_composer_supported(self):
        """Check if connector is marked as manager/composer supported."""
        manifest = self._read_file("__metadata__", "connector_manifest.json")
        if not manifest:
            return

        try:
            mdata = json.loads(manifest)
            is_supported = mdata.get("manager_supported", False)
            self.report.add(
                CheckResult(
                    check_id="config-composer",
                    title="Connector is composer/manager supported",
                    status=Status.PASS if is_supported else Status.WARN,
                    message=(
                        "" if is_supported else "manager_supported is false in manifest"
                    ),
                )
            )
        except json.JSONDecodeError:
            pass

    # =========================================================================
    # RUN ALL CHECKS
    # =========================================================================

    def run_all(self):
        """Run all verification checks. Apply fixes first if --fix is enabled."""
        if self.apply_fix:
            self.apply_all_fixes()

        # File structure
        self.check_file_structure()

        # Deprecated patterns (must NOT be present)
        self.check_no_confidence_level()
        self.check_no_helper_api()
        self.check_no_update_existing_data()
        self.check_no_helper_log()
        self.check_no_x_opencti_report_status()
        self.check_no_interval_config()

        # STIX compliance
        self.check_deterministic_ids()
        self.check_external_references()
        self.check_markings_usage()
        self.check_author_reference()
        self.check_cleanup_bundle()

        # Pattern compliance
        self.check_traceback_in_main()
        self.check_error_handling()
        self.check_connector_type_in_dockerfile()
        self.check_absolute_imports()
        self.check_helper_listen()
        self.check_playbook_compatible()
        self.check_scope_handling()
        self.check_base_settings_sdk()
        self.check_date_formatting()
        self.check_backpressure()
        self.check_work_management()
        self.check_template_structure()

        # Config checks
        self.check_dockerfile_pattern()
        self.check_docker_compose()
        self.check_env_sample()
        self.check_manifest()
        self.check_requirements()
        self.check_composer_supported()

        # README checks
        self.check_readme_completeness()
        self.check_readme_verified_table()

        # Mark fixed checks: if a fix was applied and the check now passes,
        # update its status to FIXED
        if self.apply_fix and self.report.fixes_applied:
            fixed_ids = {f.check_id for f in self.report.fixes_applied}
            for result in self.report.results:
                if result.check_id in fixed_ids and result.status == Status.PASS:
                    result.status = Status.FIXED
                    result.message = "Auto-fixed"

        return self.report


def find_all_connectors(repo_root: str, connector_type: Optional[str] = None) -> list:
    """Find all connector directories in the repository."""
    root = Path(repo_root)
    type_dirs = [
        "external-import",
        "internal-enrichment",
        "internal-export-file",
        "internal-import-file",
        "stream",
    ]

    if connector_type:
        type_dirs = [d for d in type_dirs if d == connector_type]

    connectors = []
    for type_dir in type_dirs:
        type_path = root / type_dir
        if not type_path.exists():
            continue
        for entry in sorted(type_path.iterdir()):
            if entry.is_dir() and not entry.name.startswith("."):
                # Must have at least a src/ or Dockerfile to be a connector
                if (entry / "src").exists() or (entry / "Dockerfile").exists():
                    connectors.append(str(entry))
    return connectors


def run_batch(
    repo_root: str,
    connector_type: Optional[str] = None,
    output_json: bool = False,
    fail_only: bool = False,
    apply_fix: bool = False,
) -> int:
    """Run verification on all connectors and produce a summary."""
    connectors = find_all_connectors(repo_root, connector_type)
    if not connectors:
        print(f"No connectors found in {repo_root}")
        return 1

    reports = []
    for connector_path in connectors:
        try:
            verifier = ConnectorVerifier(connector_path, apply_fix=apply_fix)
            report = verifier.run_all()
            reports.append(report)
        except Exception as e:
            # Create a minimal error report
            report = VerificationReport(
                connector_path=connector_path, connector_type="ERROR"
            )
            report.add(
                CheckResult(
                    check_id="error",
                    title="Verification failed",
                    status=Status.FAIL,
                    message=str(e),
                )
            )
            reports.append(report)

    if output_json:
        batch_result = {
            "total_connectors": len(reports),
            "connectors": [],
        }
        for report in reports:
            entry = {
                "connector": report.connector_name,
                "path": report.connector_path,
                "type": report.connector_type,
                "pass": report.pass_count,
                "fail": report.fail_count,
                "warn": report.warn_count,
                "total": report.total_checks,
                "fixes_applied": len(report.fixes_applied),
                "failed_checks": [
                    {"id": r.check_id, "title": r.title, "message": r.message}
                    for r in report.results
                    if r.status == Status.FAIL
                ],
                "warnings": [
                    {"id": r.check_id, "title": r.title, "message": r.message}
                    for r in report.results
                    if r.status == Status.WARN
                ],
            }
            if not fail_only or entry["fail"] > 0:
                batch_result["connectors"].append(entry)

        # Add aggregate stats
        total_pass = sum(r.pass_count for r in reports)
        total_fail = sum(r.fail_count for r in reports)
        total_warn = sum(r.warn_count for r in reports)
        total_fixes = sum(len(r.fixes_applied) for r in reports)
        batch_result["aggregate"] = {
            "total_pass": total_pass,
            "total_fail": total_fail,
            "total_warn": total_warn,
            "total_fixes": total_fixes,
            "clean_connectors": sum(1 for r in reports if r.fail_count == 0),
        }
        print(json.dumps(batch_result, indent=2))
    else:
        # Print summary table
        print(f"\n{'='*100}")
        print("  BATCH CONNECTOR VERIFICATION REPORT")
        print(f"  Connectors: {len(reports)}")
        if connector_type:
            print(f"  Type filter: {connector_type}")
        if apply_fix:
            print("  Mode: --fix (auto-fixes applied)")
        print(f"{'='*100}\n")

        # Table header
        name_width = max(35, max(len(r.connector_name) for r in reports) + 2)
        header = (
            f"  {'Connector':<{name_width}} {'Type':<22} "
            f"{'Pass':>5} {'Fail':>5} {'Warn':>5} {'Fix':>4} {'Score':>8}"
        )
        print(header)
        print(f"  {'-'*(len(header)-2)}")

        # Sort: failures first, then by name
        sorted_reports = sorted(
            reports, key=lambda r: (-r.fail_count, r.connector_name)
        )

        for report in sorted_reports:
            if fail_only and report.fail_count == 0:
                continue

            fixes = len(report.fixes_applied)
            score_pct = (
                f"{report.pass_count}/{report.total_checks}"
                if report.total_checks > 0
                else "N/A"
            )

            # Color-code the status indicator
            if report.fail_count == 0:
                indicator = "✅"
            elif report.fail_count <= 3:
                indicator = "⚠️ "
            else:
                indicator = "❌"

            line = (
                f"  {indicator} {report.connector_name:<{name_width-3}} "
                f"{report.connector_type:<22} "
                f"{report.pass_count:>5} {report.fail_count:>5} "
                f"{report.warn_count:>5} {fixes:>4} {score_pct:>8}"
            )
            print(line)

        # Summary
        total_connectors = len(reports)
        clean = sum(1 for r in reports if r.fail_count == 0)
        total_fail_count = sum(r.fail_count for r in reports)
        total_warn_count = sum(r.warn_count for r in reports)
        total_fixes = sum(len(r.fixes_applied) for r in reports)

        print(f"\n{'='*100}")
        print(
            f"  SUMMARY: {clean}/{total_connectors} connectors clean | "
            f"{total_fail_count} total failures | "
            f"{total_warn_count} total warnings"
        )
        if total_fixes > 0:
            print(f"  FIXES: {total_fixes} auto-fixes applied across all connectors")
        print(f"{'='*100}\n")

        # Show top issues across all connectors
        issue_counts = {}
        for report in reports:
            for result in report.results:
                if result.status == Status.FAIL:
                    issue_counts.setdefault(result.title, []).append(
                        report.connector_name
                    )

        if issue_counts:
            print("  📊 TOP ISSUES (most common failures)")
            print(f"  {'-'*60}")
            for title, connectors in sorted(
                issue_counts.items(), key=lambda x: -len(x[1])
            ):
                count = len(connectors)
                examples = ", ".join(connectors[:3])
                if count > 3:
                    examples += f", ... (+{count-3} more)"
                print(f"  [{count:>3}x] {title}")
                print(f"        {examples}")
            print()

    has_failures = any(r.fail_count > 0 for r in reports)
    return 1 if has_failures else 0


def main():
    parser = argparse.ArgumentParser(
        description="Verify OpenCTI connectors against the verification checklist"
    )
    parser.add_argument(
        "connector_path",
        nargs="?",
        help="Path to the connector directory (not needed with --batch)",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Auto-fix issues where possible (helper.log_, datetime, Dockerfile, etc.)",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Run verification on all connectors in the repository",
    )
    parser.add_argument(
        "--type",
        dest="connector_type",
        choices=[
            "external-import",
            "internal-enrichment",
            "internal-export-file",
            "internal-import-file",
            "stream",
        ],
        help="Filter to a specific connector type (only with --batch)",
    )
    parser.add_argument(
        "--fail-only",
        action="store_true",
        help="Only show connectors with failures (only with --batch)",
    )
    args = parser.parse_args()

    if args.batch:
        # Find repo root: walk up from script location to find manifest.json
        script_dir = Path(__file__).resolve().parent
        repo_root = script_dir
        for _ in range(5):
            if (repo_root / "manifest.json").exists() or (
                repo_root / "external-import"
            ).exists():
                break
            repo_root = repo_root.parent

        sys.exit(
            run_batch(
                str(repo_root),
                connector_type=args.connector_type,
                output_json=args.json,
                fail_only=args.fail_only,
                apply_fix=args.fix,
            )
        )

    if not args.connector_path:
        parser.error("connector_path is required when not using --batch")

    if not os.path.isdir(args.connector_path):
        print(f"Error: {args.connector_path} is not a directory")
        sys.exit(1)

    verifier = ConnectorVerifier(args.connector_path, apply_fix=args.fix)
    report = verifier.run_all()

    if args.json:
        print(report.to_json())
    else:
        report.print_report()

    # Exit with failure code if any FAIL results
    if Status.FAIL in report.summary():
        sys.exit(1)


if __name__ == "__main__":
    main()
