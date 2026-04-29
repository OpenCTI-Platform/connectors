"""Data models for the connector linter."""

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    """Severity levels for check results."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    def symbol(self) -> str:
        """Get a short symbol for the severity level."""
        return {"error": "E", "warning": "W", "info": "I"}[self.value]


@dataclass
class CheckFinding:
    """A single finding produced by a check function.

    Contains only the check-specific data.  The runner enriches each
    finding with the ``code``, ``name`` and ``severity`` from the
    :class:`CheckDescriptor` to produce a full :class:`CheckResult`.
    """

    message: str
    severity: Severity  # override descriptor default (rare)
    file_path: Path | None = None
    line: int | None = None
    suggestion: str | None = None


@dataclass
class CheckResult:
    """Result of a single check execution."""

    code: str
    name: str
    message: str
    severity: Severity
    file_path: Path | None = None
    line: int | None = None
    suggestion: str | None = None


@dataclass
class ConnectorContext:
    """Contextual data about a connector, loaded once and shared across checks."""

    path: Path
    connector_type: str | None = None
    manifest: dict[str, Any] = field(default_factory=dict)
    config_schema: dict[str, Any] = field(default_factory=dict)
    has_tests: bool = False
    has_dockerfile: bool = False
    has_readme: bool = False
    has_metadata_dir: bool = False
    src_files: list[Path] = field(default_factory=list)
    all_files: list[Path] = field(default_factory=list)

    @classmethod
    def load(cls, connector_path: Path) -> "ConnectorContext":
        """Load connector context from its directory."""
        ctx = cls(path=connector_path.resolve())

        # Detect connector type from parent directory name
        parent_name = ctx.path.parent.name
        type_mapping = {
            "external-import": "EXTERNAL_IMPORT",
            "internal-enrichment": "INTERNAL_ENRICHMENT",
            "internal-export-file": "INTERNAL_EXPORT_FILE",
            "internal-import-file": "INTERNAL_IMPORT_FILE",
            "stream": "STREAM",
        }
        ctx.connector_type = type_mapping.get(parent_name)
        # Fallback only for template layout: templates/<connector-kind>
        if ctx.connector_type is None and parent_name == "templates":
            ctx.connector_type = type_mapping.get(ctx.path.name)

        # Load manifest
        manifest_path = ctx.path / "__metadata__" / "connector_manifest.json"
        if manifest_path.exists():
            with manifest_path.open() as f:
                ctx.manifest = json.load(f)

        # Fallback: use container_type from manifest
        if ctx.connector_type is None and ctx.manifest.get("container_type"):
            ctx.connector_type = ctx.manifest["container_type"]

        if ctx.connector_type is None:
            raise ValueError(
                "Unable to determine connector type for "
                f"'{ctx.path}'. Expected a connector directory nested under one "
                "of: external-import, internal-enrichment, internal-export-file, "
                "internal-import-file, stream, or templates/<connector-kind>; "
                "or provide '__metadata__/connector_manifest.json' with "
                "'container_type'."
            )

        # Load config schema
        schema_path = ctx.path / "__metadata__" / "connector_config_schema.json"
        if schema_path.exists():
            with schema_path.open() as f:
                ctx.config_schema = json.load(f)

        # Detect structural elements
        ctx.has_metadata_dir = (ctx.path / "__metadata__").is_dir()
        ctx.has_tests = (ctx.path / "tests").is_dir()
        ctx.has_dockerfile = (ctx.path / "Dockerfile").is_file()
        ctx.has_readme = (ctx.path / "README.md").is_file()

        # Collect file lists
        ctx.all_files = [
            p.relative_to(ctx.path) for p in ctx.path.rglob("*") if p.is_file()
        ]
        ctx.src_files = [
            p.relative_to(ctx.path)
            for p in (ctx.path / "src").rglob("*.py")
            if p.is_file()
        ]

        return ctx
