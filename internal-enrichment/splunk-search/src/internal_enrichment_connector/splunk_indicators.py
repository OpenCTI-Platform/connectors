from __future__ import annotations

import re
from dataclasses import dataclass, field

from internal_enrichment_connector.utils.note_params import load_note_params
from pycti import OpenCTIConnectorHelper


@dataclass(frozen=True)
class SplunkSearchPlan:
    indicator_id: str
    name: str
    obs_type: str
    query: str
    earliest: str
    latest: str
    index_scope: str | None = None
    tokens_used: dict[str, str] = field(default_factory=dict)
    # Custom search fields (set when Note contains a "search" param)
    custom: bool = False
    observable_field: str = "observable_value"
    observable_type_override: str | None = None
    indicator_value: str = ""


class SplunkIndicator:
    """Translate a STIX Indicator + params into a concrete Splunk search.

    Responsibilities:
      - Load per-indicator params from OpenCTI Notes (JSON content)
      - Safely render the SPL template (replace placeholders)
      - Produce a SplunkSearchPlan (query + earliest/latest bounds)
    """

    def __init__(self, indicator: dict, obs_type: str) -> None:
        self.indicator = indicator
        self.id = indicator.get("standard_id") or indicator.get("id", "")
        self.opencti_id = indicator.get("x_opencti_id") or indicator.get("id", "")
        self.name = indicator.get("name", "(unnamed indicator)")
        self.pattern = indicator.get("pattern", "")
        self.pattern_type = indicator.get("pattern_type", "")
        self.obs_type = obs_type or indicator.get("x_opencti_main_observable_type", "")
        self.params: dict[str, str] = {}

    # ---------------------------- OpenCTI params ---------------------------- #

    @staticmethod
    def extract_spl(indicator: dict) -> str | None:
        """Extract the raw SPL query from an indicator dict.

        For indicators with pattern_type='spl', the pattern field IS the SPL query.
        Returns the query string, or None when the indicator is not an SPL type
        or the pattern is empty.
        """
        pattern_type = (indicator.get("pattern_type") or "").lower().strip()
        if pattern_type == "spl":
            query = (indicator.get("pattern") or "").strip()
            return query if query else None
        return None

    def load_params_from_notes(self, helper: OpenCTIConnectorHelper) -> None:
        """Fetch attached Notes and merge any YAML content as params.

        Expected Note.content should be a YAML mapping, for example::

            earliest: -7d@d
            latest: now
            index_scope: index=security
        """
        helper.connector_logger.debug(
            "[PARAMS] Indicator OpenCTI ID resolved",
            {"opencti_id": self.opencti_id, "stix_id": self.id},
        )
        try:
            notes = (
                helper.api.note.list(
                    filters={
                        "mode": "and",
                        "filters": [
                            {
                                "key": "note_types",
                                "operator": "eq",
                                "values": ["Search Parameters"],
                                "mode": "or",
                            },
                            {
                                "key": "objects",
                                "operator": "eq",
                                "values": [self.opencti_id],
                                "mode": "or",
                            },
                        ],
                        "filterGroups": [],
                    }
                )
                or []
            )
            helper.connector_logger.debug(
                "[PARAMS] Notes fetched", {"indicator_id": self.id, "count": len(notes)}
            )
        except Exception as e:
            helper.connector_logger.warning(
                "[PARAMS] Note.list failed", {"error": str(e)}
            )
            notes = []

        merged: dict = {}
        for n in notes:
            content = (n or {}).get("content", "") or ""
            note_params = load_note_params(content)
            if note_params:
                merged.update(note_params)
            elif content.strip():
                helper.connector_logger.debug(
                    "[PARAMS] Skipped non-YAML or empty Note content",
                    {"note_id": (n or {}).get("id")},
                )

        self.params = merged
        helper.connector_logger.debug("[PARAMS] Merged params", {"params": self.params})

    # ---------------------------- Rendering ---------------------------- #
    def render(
        self, values: list[str], helper: OpenCTIConnectorHelper | None = None
    ) -> SplunkSearchPlan:
        safe_vals = [self._escape(str(v)) for v in values if v is not None]
        value_str = safe_vals[0] if safe_vals else ""
        values_csv = ",".join([f'"{v}"' for v in safe_vals]) if safe_vals else ""

        earliest = self.params.get("earliest", "-30d@d")
        latest = self.params.get("latest", "now")
        observable_field = self.params.get("observable_field", "observable_value")
        observable_type_override = self.params.get("observable_type") or None

        # --- Custom search path: Note contains a "search" param ---
        custom_spl = self.params.get("search")
        if custom_spl:
            q = custom_spl
            # Substitute {indicator_value} and {indicator_id} placeholders
            q = q.replace("{indicator_value}", value_str)
            q = q.replace("{indicator_id}", self.id)
            # Warn if any braces remain (likely a typo in a placeholder name)
            if "{" in q or "}" in q:
                log_fn = helper.connector_logger.warning if helper else None
                if log_fn:
                    log_fn(
                        "[CUSTOM] Rendered SPL still contains braces — possible unresolved placeholder",
                        {"query_preview": q[:200]},
                    )
            return SplunkSearchPlan(
                indicator_id=self.id,
                name=self.name,
                obs_type=(self.obs_type or ""),
                query=q,
                earliest=earliest,
                latest=latest,
                index_scope=self.params.get("index_scope"),
                tokens_used={"value": value_str, "values_csv": values_csv},
                custom=True,
                observable_field=observable_field,
                observable_type_override=observable_type_override,
                indicator_value=value_str,
            )

        # --- Built-in template path ---
        q = self.pattern or ""
        # Angle-bracket substitutions
        angle_map = {
            "VALUE": value_str,
            "VALUE_LIST": values_csv,
            "OBS_VALUE": value_str,
            "OBS_LIST": values_csv,
            "INDICATOR_ID": self.id,
            "DOMAIN_LIST": values_csv,
            "IP_LIST": values_csv,
            "HOSTNAME_LIST": values_csv,
            "FILE_HASH_LIST": values_csv,
        }
        for k, v in angle_map.items():
            q = q.replace(f"<{k}>", v)

        # Mustache substitutions
        mustache_map = {
            "value": value_str,
            "values_csv": values_csv,
            "indicator_id": self.id,
            "obs_type": (self.obs_type or ""),
        }
        q = re.sub(
            r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}",
            lambda m: mustache_map.get(m.group(1).strip().lower(), m.group(0)),
            q,
        )

        self._assert_no_unresolved(q)

        index_scope = self.params.get("index_scope")
        if index_scope:
            # Prepend scope to the leftmost search segment
            if "|" in q:
                left, pipe, right = q.partition("|")
                q = f"{index_scope} {left.strip()} | {right}"
            else:
                q = f"{index_scope} {q}"

        return SplunkSearchPlan(
            indicator_id=self.id,
            name=self.name,
            obs_type=(self.obs_type or ""),
            query=q,
            earliest=earliest,
            latest=latest,
            index_scope=index_scope,
            tokens_used={"value": value_str, "values_csv": values_csv},
            custom=False,
            observable_field=observable_field,
            observable_type_override=observable_type_override,
            indicator_value=value_str,
        )

    # ---------------------------- helpers ---------------------------- #
    def _escape(self, s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    def _assert_no_unresolved(self, q: str) -> None:
        if "<" in q and ">" in q:
            # very naive check; good enough for our templates
            raise ValueError(f"Unresolved <PLACEHOLDER> in query for {self.id}")
