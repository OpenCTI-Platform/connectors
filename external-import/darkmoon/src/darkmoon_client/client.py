"""Client reading the Darkmoon OSS findings store from disk.

Unlike most external-import connectors, Darkmoon's findings are not fetched over
HTTP: the Darkmoon OSS engine writes them to its data directory during a
campaign. This client reads those JSON files from a local path (mounted into the
connector container) and validates them into the typed models in ``models.py``.

Expected directory layout (the directory the Darkmoon stack mounts at
``/root/.local/share/opencode``)::

    <export_path>/
        campaigns/<campaign_id>.json        # one DarkmoonCampaign per file
        vulnerabilities/<campaign_id>.json  # a list of DarkmoonFinding
        targets.json                        # a list of DarkmoonTarget (optional)

It never connects to the Darkmoon web dashboard or any API.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from darkmoon_client.models import (
    CampaignBundle,
    DarkmoonCampaign,
    DarkmoonFinding,
    DarkmoonTarget,
)


class DarkmoonExportError(Exception):
    """Raised when the Darkmoon export directory cannot be read."""


def parse_darkmoon_datetime(value: str | None) -> datetime | None:
    """Parse a Darkmoon timestamp (ISO 8601, e.g. '2026-10-07T12:30:01Z').

    Returns a timezone-aware ``datetime`` (assuming UTC when no offset is
    present), or ``None`` if the value is missing or unparsable.
    """
    if not value:
        return None
    raw = str(value).strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class DarkmoonClient:
    """Read and validate the Darkmoon OSS findings store from disk."""

    def __init__(self, export_path: str | Path, logger: Any):
        """Initialize the client.

        Args:
            export_path: Path to the Darkmoon OSS data directory.
            logger: The connector logger, used to record read/parse issues.
        """
        self._base = Path(export_path)
        self._logger = logger

    @property
    def campaigns_dir(self) -> Path:
        return self._base / "campaigns"

    @property
    def vulnerabilities_dir(self) -> Path:
        return self._base / "vulnerabilities"

    @property
    def targets_file(self) -> Path:
        return self._base / "targets.json"

    def _resolve_within_base(self, candidate: Path) -> Path | None:
        """Resolve ``candidate`` and confirm it stays inside the export root.

        Paths handed to :meth:`_read_json` are partly derived from the export
        JSON (e.g. a campaign id becomes a ``vulnerabilities/<id>.json`` path)
        and the export directory may contain symlinks. Resolving both the base
        and the candidate (following ``..`` and symlinks) and rejecting anything
        that escapes the base prevents reading arbitrary files outside the
        mounted export directory.

        Returns the resolved path, or ``None`` when it escapes the export root.
        """
        try:
            base = self._base.resolve(strict=False)
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError) as err:
            self._logger.warning(
                "[Darkmoon] Could not resolve path, skipping it",
                {"path": str(candidate), "error": str(err)},
            )
            return None
        if resolved != base and base not in resolved.parents:
            self._logger.warning(
                "[Darkmoon] Refusing to read a path outside the export directory",
                {"path": str(candidate), "export_path": str(base)},
            )
            return None
        return resolved

    def _read_json(self, path: Path) -> Any:
        """Read a JSON file, returning ``None`` on a missing/invalid/unsafe file."""
        resolved = self._resolve_within_base(path)
        if resolved is None or not resolved.is_file():
            return None
        try:
            with resolved.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError) as err:
            self._logger.warning(
                "[Darkmoon] Could not read JSON file, skipping it",
                {"path": str(resolved), "error": str(err)},
            )
            return None

    def _load_targets(self) -> dict[str, DarkmoonTarget]:
        """Load ``targets.json`` into a mapping keyed by target id."""
        data = self._read_json(self.targets_file)
        targets: dict[str, DarkmoonTarget] = {}
        if isinstance(data, list):
            for raw in data:
                if not isinstance(raw, dict):
                    continue
                try:
                    target = DarkmoonTarget(**raw)
                    targets[target.id] = target
                except Exception as err:  # noqa: BLE001 - one bad record must not abort
                    self._logger.warning(
                        "[Darkmoon] Could not parse target, skipping it",
                        {"error": str(err)},
                    )
        return targets

    def _load_findings(self, campaign_id: str) -> list[DarkmoonFinding]:
        """Load and validate the findings file for a campaign."""
        data = self._read_json(self.vulnerabilities_dir / f"{campaign_id}.json")
        findings: list[DarkmoonFinding] = []
        if isinstance(data, list):
            for raw in data:
                if not isinstance(raw, dict):
                    continue
                try:
                    findings.append(DarkmoonFinding(**raw))
                except Exception as err:  # noqa: BLE001 - skip one malformed finding
                    self._logger.warning(
                        "[Darkmoon] Could not parse finding, skipping it",
                        {"campaign_id": campaign_id, "error": str(err)},
                    )
        return findings

    def collect(self, since: datetime | None = None) -> list[CampaignBundle]:
        """Collect campaign bundles whose date is strictly after ``since``.

        Args:
            since: Only campaigns dated strictly after this moment are returned.
                When ``None``, every campaign is returned.

        Returns:
            A list of ``CampaignBundle`` sorted by ascending campaign date.

        Raises:
            DarkmoonExportError: If the export directory does not exist.
        """
        if not self._base.exists():
            raise DarkmoonExportError(
                f"Darkmoon export path does not exist: {self._base}"
            )
        if not self.campaigns_dir.exists():
            self._logger.warning(
                "[Darkmoon] No 'campaigns' directory found under export path, "
                "nothing to import",
                {"export_path": str(self._base)},
            )
            return []

        targets = self._load_targets()
        bundles: list[CampaignBundle] = []

        for campaign_file in sorted(self.campaigns_dir.glob("*.json")):
            raw = self._read_json(campaign_file)
            if not isinstance(raw, dict):
                continue
            try:
                campaign = DarkmoonCampaign(**raw)
            except Exception as err:  # noqa: BLE001 - skip one malformed campaign
                self._logger.warning(
                    "[Darkmoon] Could not parse campaign, skipping it",
                    {"path": str(campaign_file), "error": str(err)},
                )
                continue

            campaign_date = parse_darkmoon_datetime(campaign.date)
            if campaign_date is None:
                # Without a usable date the campaign cannot be filtered by
                # ``since`` nor checkpointed, and the processor would fall back
                # to ``datetime.now()`` for the Report publication date, which
                # the SDK uses to derive the Report id. That would emit a brand
                # new Report on every run, so skip undated campaigns instead.
                self._logger.warning(
                    "[Darkmoon] Campaign has no parseable date, skipping it",
                    {"campaign_id": campaign.id, "date": campaign.date},
                )
                continue
            if since is not None and campaign_date <= since:
                continue

            findings = self._load_findings(campaign.id)
            if not findings:
                # A campaign with no findings carries no intelligence to import.
                continue

            target = targets.get(campaign.target_id) if campaign.target_id else None
            bundles.append(
                CampaignBundle(campaign=campaign, findings=findings, target=target)
            )

        bundles.sort(
            key=lambda b: parse_darkmoon_datetime(b.campaign.date)
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return bundles
