from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pycti import OpenCTIConnectorHelper
import json
import re


@dataclass(frozen=True)
class SplunkSearchPlan:
    indicator_id: str
    name: str
    obs_type: str
    query: str
    earliest: str
    latest: str
    index_scope: Optional[str] = None
    tokens_used: Dict[str, str] = field(default_factory=dict)


class SplunkIndicator:
    """Translate a STIX Indicator + params into a concrete Splunk search.

    Responsibilities:
      - Load per-indicator params from OpenCTI Notes (JSON content)
      - Safely render the SPL template (replace placeholders)
      - Produce a SplunkSearchPlan (query + earliest/latest bounds)
    """

    def __init__(self, indicator: dict, obs_type: str) -> None:
        self.indicator = indicator
        self.id = indicator.get("id", "")
        self.opencti_id = indicator.get("x_opencti_id", "")
        self.name = indicator.get("name", "(unnamed indicator)")
        self.pattern = indicator.get("pattern", "")
        self.pattern_type = indicator.get("pattern_type", "")
        self.obs_type = obs_type or indicator.get("x_opencti_main_observable_type", "")
        self.params: Dict[str, str] = {}

    # ---------------------------- OpenCTI params ---------------------------- #

    def load_params_from_notes(self, helper: OpenCTIConnectorHelper) -> None:
        """Fetch attached Notes and merge any JSON content as params.

        Expected Note.content can be raw JSON or JSON inside a fenced code block:
        ```json
        { "earliest": "-7d@d", "latest": "now", "index_scope": "index=security" }
        ```
        """
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

        merged: Dict[str, str] = {}
        for n in notes:
            content = (n or {}).get("content", "") or ""
            if not content.strip():
                continue

            # Try raw JSON first
            parsed = None
            try:
                parsed = json.loads(content)
            except Exception:
                # Try to extract fenced ```json ... ``` (or ``` ... ```) blocks
                fenced = re.findall(
                    r"```(?:json)?\s*([\s\S]*?)```", content, flags=re.I
                )
                for block in fenced:
                    try:
                        parsed = json.loads(block)
                        break
                    except Exception:
                        continue

            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if isinstance(v, (str, int, float)):
                        merged[k] = str(v)
            else:
                helper.connector_logger.debug(
                    "[PARAMS] Skipped non-JSON Note content",
                    {"note_id": (n or {}).get("id")},
                )

        self.params = merged
        helper.connector_logger.debug("[PARAMS] Merged params", {"params": self.params})

    # ---------------------------- Rendering ---------------------------- #
    def render(self, values: List[str]) -> SplunkSearchPlan:
        safe_vals = [self._escape(str(v)) for v in values if v is not None]
        value_str = safe_vals[0] if safe_vals else ""
        values_csv = ",".join([f'"{v}"' for v in safe_vals]) if safe_vals else ""

        q = self.pattern or ""
        # Angle-bracket substitutions
        angle_map = {
            "VALUE": value_str,
            "VALUE_LIST": values_csv,
            "OBS_VALUE": value_str,
            "OBS_LIST": values_csv,
            "INDICATOR_ID": self.id,
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

        earliest = self.params.get("earliest", "-30d@d")
        latest = self.params.get("latest", "now")
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
        )

    # ---------------------------- helpers ---------------------------- #
    def _escape(self, s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    def _assert_no_unresolved(self, q: str) -> None:
        if "<" in q and ">" in q:
            # very naive check; good enough for our templates
            raise ValueError(f"Unresolved <PLACEHOLDER> in query for {self.id}")
