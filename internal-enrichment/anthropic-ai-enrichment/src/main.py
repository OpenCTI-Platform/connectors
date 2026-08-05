import json
import os
import re
import time

import anthropic
from pycti import OpenCTIConnectorHelper

SYSTEM_PROMPT = """You are a senior cyber threat intelligence analyst.
Analyze threat intelligence content and return structured JSON only.
No prose, no markdown fences, no explanation; return raw JSON."""

REPORT_PROMPT = """Analyze this threat intelligence report. Return JSON with exactly these keys:
- summary: string, 2-3 sentence executive brief
- threat_actors: list of strings containing actor names, aliases, or groups mentioned
- malware_families: list of strings containing malware or tool names
- attack_techniques: list of strings containing MITRE ATT&CK IDs only, for example ["T1059.001", "T1003"]
- targeted_sectors: list of strings
- targeted_countries: list of ISO 3166-1 alpha-2 country codes
- confidence: integer from 0 to 100

Report:
{content}"""

INTRUSION_SET_PROMPT = """Analyze this threat actor or intrusion set profile. Return JSON with exactly these keys:
- summary: string, 2-3 sentence executive brief
- aliases: list of strings
- malware_families: list of strings containing malware or tool names
- attack_techniques: list of strings containing MITRE ATT&CK IDs only, for example ["T1059.001", "T1003"]
- targeted_sectors: list of strings
- targeted_countries: list of ISO 3166-1 alpha-2 country codes
- motivation: string, one of "espionage", "financial", "hacktivism", "destruction", "unknown"
- sophistication: string, one of "minimal", "intermediate", "advanced", "expert", "unknown"
- confidence: integer from 0 to 100

Profile:
{content}"""

# MITRE ATT&CK technique/sub-technique identifiers, e.g. "T1059" or "T1059.001".
ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Anthropic API errors that are worth retrying: transport-level failures and the
# server's own transient 5xx errors. Client errors (bad request, auth, permission,
# not found, etc.) will never succeed on retry, so they are not included here.
RETRYABLE_API_ERRORS = (
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
    anthropic.InternalServerError,
)


def normalize_string_list(value) -> list[str]:
    """Coerce AI-provided output into a list of non-empty strings.

    The model is asked for a JSON list, but nothing stops it from returning a
    bare string, null, or a list containing non-string/empty items. Iterating
    over an unvalidated string would loop over its characters instead of
    treating it as a single value.
    """
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def normalize_attack_ids(value) -> list[str]:
    """Like normalize_string_list, but also drops anything that isn't a
    well-formed MITRE ATT&CK technique ID, so malformed model output can't
    create bogus Attack Pattern objects."""
    return [
        item.upper()
        for item in normalize_string_list(value)
        if ATTACK_ID_RE.match(item.upper())
    ]


class AnthropicAIEnrichmentConnector:
    def __init__(self):
        config = {
            "opencti": {
                "url": os.environ.get("OPENCTI_URL", "http://opencti:8080"),
                "token": os.environ["OPENCTI_TOKEN"],
            },
            "connector": {
                "id": os.environ["CONNECTOR_ID"],
                "type": "INTERNAL_ENRICHMENT",
                "name": os.environ.get("CONNECTOR_NAME", "Anthropic AI Enrichment"),
                "scope": os.environ.get(
                    "CONNECTOR_SCOPE",
                    "Report,Intrusion-Set,Threat-Actor-Group,Malware",
                ),
                "log_level": os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
                "auto": False,
            },
        }
        self.helper = OpenCTIConnectorHelper(config)
        self.client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.model = os.environ.get("AI_MODEL", "claude-3-5-haiku-latest")

    def _call_anthropic(self, prompt_template: str, content: str) -> dict | None:
        prompt = prompt_template.format(content=content[:8000])
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                msg = self.client.messages.create(
                    model=self.model,
                    max_tokens=2048,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                return json.loads(msg.content[0].text)
            except anthropic.RateLimitError as exc:
                last_error = exc
                wait_seconds = 60 * (attempt + 1)
                self.helper.log_warning(f"Rate limited; waiting {wait_seconds}s")
                time.sleep(wait_seconds)
            except json.JSONDecodeError as exc:
                last_error = exc
                self.helper.log_warning(
                    f"AI response was not valid JSON (attempt {attempt + 1}/3): {exc}"
                )
            except RETRYABLE_API_ERRORS as exc:
                last_error = exc
                wait_seconds = 5 * (attempt + 1)
                self.helper.log_warning(
                    f"Anthropic API transient error (attempt {attempt + 1}/3): "
                    f"{exc}; waiting {wait_seconds}s"
                )
                time.sleep(wait_seconds)
            except anthropic.APIError as exc:
                # Non-retryable (bad request, auth, permission, not found, ...).
                self.helper.log_error(
                    f"AI enrichment failed with a non-retryable error: {exc}"
                )
                return None
        self.helper.log_error(f"AI enrichment failed after 3 attempts: {last_error}")
        return None

    def _safe_confidence(self, raw_confidence, default: int = 50) -> int:
        """Parse the AI-provided confidence defensively and cap it at the
        connector's own configured confidence level, matching the convention
        used by other internal-enrichment connectors in this repo."""
        try:
            confidence = int(float(raw_confidence))
        except (TypeError, ValueError):
            confidence = default
        confidence = max(0, min(100, confidence))
        max_confidence = self.helper.connect_confidence_level
        if isinstance(max_confidence, int):
            confidence = min(confidence, max_confidence)
        return confidence

    def _add_note(self, entity_id: str, summary: str, confidence: int) -> None:
        self.helper.api.note.create(
            abstract="AI Summary",
            content=summary,
            confidence=confidence,
            object_ids=[entity_id],
        )

    def _read_by_name(self, api_client, name: str) -> dict | None:
        return api_client.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [name]}],
                "filterGroups": [],
            }
        )

    def _link_threat_actors(self, entity_id: str, names: list, confidence: int) -> None:
        for name in normalize_string_list(names):
            actor = self._read_by_name(self.helper.api.threat_actor_group, name)
            if actor:
                self.helper.api.stix_core_relationship.create(
                    fromId=entity_id,
                    toId=actor["id"],
                    relationship_type="related-to",
                    confidence=confidence,
                )

    def _link_malware(self, entity_id: str, names: list, confidence: int) -> None:
        for name in normalize_string_list(names):
            malware = self._read_by_name(self.helper.api.malware, name)
            if malware:
                self.helper.api.stix_core_relationship.create(
                    fromId=entity_id,
                    toId=malware["id"],
                    relationship_type="uses",
                    confidence=confidence,
                )

    def _link_attack_patterns(
        self, entity_id: str, technique_ids: list, confidence: int
    ) -> None:
        for technique_id in normalize_attack_ids(technique_ids):
            pattern = self.helper.api.attack_pattern.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "x_mitre_id", "values": [technique_id]}],
                    "filterGroups": [],
                }
            )
            if not pattern:
                pattern = self.helper.api.attack_pattern.create(
                    name=technique_id,
                    x_mitre_id=technique_id,
                    confidence=50,
                )
            if pattern:
                self.helper.api.stix_core_relationship.create(
                    fromId=entity_id,
                    toId=pattern["id"],
                    relationship_type="uses",
                    confidence=confidence,
                )

    def _update_score(self, entity_id: str, confidence: int) -> None:
        self.helper.api.stix_domain_object.update_field(
            id=entity_id,
            input={"key": "x_opencti_score", "value": str(confidence)},
        )

    def _enrich_report(self, report: dict) -> str:
        content = report.get("description") or report.get("name") or ""
        if len(content) < 10:
            return "Skipped: content too short"

        result = self._call_anthropic(REPORT_PROMPT, content)
        if not result:
            return "Skipped: AI error"

        confidence = self._safe_confidence(result.get("confidence"))
        entity_id = report["id"]

        if result.get("summary"):
            self._add_note(entity_id, result["summary"], confidence)
        self._link_threat_actors(entity_id, result.get("threat_actors", []), confidence)
        self._link_malware(entity_id, result.get("malware_families", []), confidence)
        self._link_attack_patterns(
            entity_id, result.get("attack_techniques", []), confidence
        )
        self._update_score(entity_id, confidence)
        return "Enriched"

    def _enrich_intrusion_set(self, entity: dict) -> str:
        content = entity.get("description") or entity.get("name") or ""
        if len(content) < 10:
            return "Skipped: content too short"

        result = self._call_anthropic(INTRUSION_SET_PROMPT, content)
        if not result:
            return "Skipped: AI error"

        confidence = self._safe_confidence(result.get("confidence"))
        entity_id = entity["id"]

        if result.get("summary"):
            self._add_note(entity_id, result["summary"], confidence)
        self._link_malware(entity_id, result.get("malware_families", []), confidence)
        self._link_attack_patterns(
            entity_id, result.get("attack_techniques", []), confidence
        )
        self._update_score(entity_id, confidence)
        return "Enriched"

    def _read_entity(self, entity_type: str, entity_id: str) -> dict:
        if entity_type == "report":
            return self.helper.api.report.read(id=entity_id) or {}
        if entity_type == "malware":
            return self.helper.api.malware.read(id=entity_id) or {}
        if entity_type == "intrusion-set":
            return self.helper.api.intrusion_set.read(id=entity_id) or {}
        if entity_type == "threat-actor-group":
            return self.helper.api.threat_actor_group.read(id=entity_id) or {}
        return {}

    def process_message(self, data: dict) -> str:
        entity_type = data.get("entity_type", "").lower()
        entity_id = data.get("entity_id")
        entity = data.get("enrichment_entity") or {}

        self.helper.log_info(
            f"Received enrichment request for {entity_type} {entity_id}"
        )
        if not entity_id:
            return "Skipped: missing entity id"

        if not entity:
            entity = self._read_entity(entity_type, entity_id)
        if not entity:
            return "Skipped: entity not found"

        if entity_type == "report":
            return self._enrich_report(entity)
        if entity_type in ("intrusion-set", "threat-actor-group", "malware"):
            return self._enrich_intrusion_set(entity)
        return "Skipped: unsupported entity type"

    def start(self):
        self.helper.log_info("Anthropic AI Enrichment connector starting")
        self.helper.listen(self.process_message)


if __name__ == "__main__":
    AnthropicAIEnrichmentConnector().start()
