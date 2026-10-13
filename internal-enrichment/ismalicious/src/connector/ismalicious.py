"""
isMalicious OpenCTI Internal Enrichment Connector

Enriches IP addresses and domains with threat intelligence from isMalicious.com
"""

from math import isfinite
from typing import Any, Dict, List, Optional

import requests
import stix2
from pycti import (
    STIX_EXT_OCTI_SCO,
    Location,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixSightingRelationship,
)

from .settings import ConnectorSettings

# Identifies the connector to the isMalicious API, which attributes usage by
# User-Agent prefix (the requests default would read as a generic script).
CONNECTOR_VERSION = "1.0.1"
USER_AGENT = f"ismalicious-opencti/{CONNECTOR_VERSION} (+https://ismalicious.com)"

# Threat category mapping to OpenCTI labels
THREAT_CATEGORY_LABELS = {
    "phishing": "phishing",
    "malware": "malware",
    "c2": "command-and-control",
    "spam": "spam",
    "botnet": "botnet",
    "cryptomining": "cryptomining",
    "adware": "adware",
    "tracking": "tracking",
    "ransomware": "ransomware",
    "exploit": "exploit-kit",
    "scam": "scam",
    "suspicious": "suspicious",
}

# Hints logged for the HTTP errors an operator can act on
HTTP_ERROR_HINTS = {
    401: "API key rejected, check ISMALICIOUS_API_KEY",
    403: "API key not allowed to call this endpoint",
    429: "rate limit or request quota reached, retry later",
}


def is_threat_source(source: Any) -> bool:
    """Tell whether a `sources[]` row of a /check response is a detection.

    Rows carry a `threatClass`: `threat` (the default when absent),
    `infrastructure` (cloud ranges, Tor exits, DoH resolvers), `policy`
    (ads, tracking) or `allowlist`. Only `threat` rows say the observable
    was seen doing harm; the others describe what it is.
    """
    if not isinstance(source, dict):
        return False
    return source.get("threatClass") in (None, "", "threat")


def threat_sources(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the detection rows of a /check response, in response order."""
    return [source for source in data.get("sources") or [] if is_threat_source(source)]


class IsMaliciousConnector:
    """OpenCTI connector for isMalicious threat intelligence."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.api_url = config.ismalicious.api_url.rstrip("/")
        self.api_key = config.ismalicious.api_key.get_secret_value()

        # Create labels for threat categories
        self._ensure_labels()

    def _ensure_labels(self) -> None:
        """Ensure required labels exist in OpenCTI."""
        label_colors = {
            "malicious": "#f44336",  # Red
            "phishing": "#e91e63",  # Pink
            "malware": "#9c27b0",  # Purple
            "command-and-control": "#673ab7",  # Deep Purple
            "botnet": "#3f51b5",  # Indigo
            "ransomware": "#f44336",  # Red
            "spam": "#ff9800",  # Orange
            "cryptomining": "#795548",  # Brown
            "scam": "#ff5722",  # Deep Orange
            "exploit-kit": "#b71c1c",  # Dark Red
            "suspicious": "#ffc107",  # Amber
        }

        for label, color in label_colors.items():
            try:
                self.helper.api.label.read_or_create_unchecked(value=label, color=color)
            except Exception as e:
                self.helper.log_warning(f"Could not create label {label}: {e}")

    def _call_api(self, observable_value: str) -> Optional[Dict[str, Any]]:
        """Call isMalicious API to check an observable."""
        try:
            response = requests.get(
                f"{self.api_url}/check",
                params={"query": observable_value, "enrichment": "standard"},
                headers={
                    "X-API-KEY": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            hint = HTTP_ERROR_HINTS.get(status, str(e))
            self.helper.log_error(f"API call failed for {observable_value}: {hint}")
            return None
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"API call failed for {observable_value}: {e}")
            return None

    def _calculate_score(self, data: Dict[str, Any]) -> Optional[int]:
        """Return the API risk score, or None when no usable score is available."""
        risk_score = data.get("riskScore")
        if isinstance(risk_score, dict):
            score = risk_score.get("score")
            # bool is an int in Python, but is not a numeric API risk score.
            if (
                isinstance(score, (int, float))
                and not isinstance(score, bool)
                and isfinite(score)
            ):
                return min(100, max(0, int(score)))

        # A missing score or malicious=False is not evidence of low risk.
        # Do not overwrite an existing OpenCTI score with a fabricated value.
        return None

    def _get_labels(self, data: Dict[str, Any]) -> List[str]:
        """Extract labels from isMalicious response."""
        labels = []

        # Add malicious label if applicable
        if data.get("malicious", False):
            labels.append("malicious")

        # Category labels come from the detection rows only: an ad-blocking
        # list or a cloud range carries a category but is not a detection
        for source in threat_sources(data):
            if category := source.get("category"):
                if mapped := THREAT_CATEGORY_LABELS.get(category.lower()):
                    if mapped not in labels:
                        labels.append(mapped)

        return labels

    def _get_external_references(
        self, data: Dict[str, Any], observable_value: str
    ) -> List[Dict[str, str]]:
        """Build external references from sources."""
        refs = []

        # Add isMalicious reference with UTM tracking
        report_url = (
            f"https://ismalicious.com/report?query={observable_value}"
            "&utm_source=opencti&utm_medium=integration&utm_campaign=connector"
        )
        refs.append(
            {
                "source_name": "isMalicious",
                "url": report_url,
                "description": "isMalicious threat intelligence report",
            }
        )

        # Add source references; non-detection rows are kept as context
        for source in data.get("sources") or []:
            if not isinstance(source, dict):
                continue
            ref = {
                "source_name": source.get("name", "Unknown"),
            }
            if url := source.get("url"):
                ref["url"] = url
            if category := source.get("category"):
                if is_threat_source(source):
                    ref["description"] = f"Detected as: {category}"
                else:
                    threat_class = source.get("threatClass")
                    ref["description"] = f"Listed as: {category} ({threat_class})"
            refs.append(ref)

        return refs

    def _create_location_and_sighting(
        self,
        stix_entity: Dict,
        geo_data: Dict[str, Any],
        stix_objects: List,
    ) -> None:
        """Create Location entity and Sighting relationship from geo data."""
        country_code = geo_data.get("countryCode") or geo_data.get("country")
        if not country_code:
            return

        country_name = geo_data.get("country", country_code)

        # Create Location (Country)
        location = stix2.Location(
            id=Location.generate_id(country_name, "Country"),
            name=country_name,
            country=country_code,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [country_code],
            },
        )
        stix_objects.append(location)

        # Create Sighting
        sighting = stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                stix_entity["id"],
                location.id,
            ),
            where_sighted_refs=[location.id],
            count=1,
            # Use fake indicator ref (OpenCTI uses custom property)
            sighting_of_ref="indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e",
            custom_properties={"x_opencti_sighting_of_ref": stix_entity["id"]},
        )
        stix_objects.append(sighting)

    def _entity_in_scope(self, data: Dict) -> bool:
        """Check the entity type, taken from its STIX id, against the connector scope."""
        scopes = [scope.lower() for scope in self.config.connector.scope]
        entity_type = data["entity_id"].split("--")[0].lower()
        return entity_type in scopes

    def _skip(self, data: Dict, reason: str) -> str:
        """
        Skip the entity. A playbook waits for a bundle to continue: when the
        message comes from a playbook (no `event_type`), send the original
        bundle back unchanged.
        """
        if not data.get("event_type"):
            self.helper.send_stix2_bundle(
                self.helper.stix2_create_bundle(data["stix_objects"])
            )
        return reason

    def _process_message(self, data: Dict) -> str:
        """Process enrichment request from OpenCTI."""
        opencti_entity = data["enrichment_entity"]
        stix_entity = data["stix_entity"]
        stix_objects = data["stix_objects"]

        if not self._entity_in_scope(data):
            return self._skip(data, "Entity not in connector scope, skipping")

        # Check TLP
        tlp = "TLP:CLEAR"
        for marking in opencti_entity.get("objectMarking", []):
            if marking.get("definition_type") == "TLP":
                tlp = marking.get("definition", tlp)

        if not OpenCTIConnectorHelper.check_max_tlp(
            tlp, self.config.ismalicious.max_tlp
        ):
            return self._skip(data, "TLP too high, skipping enrichment")

        # Get observable value and type
        observable_value = stix_entity.get("value")
        entity_type = opencti_entity.get("entity_type", "").lower()

        if not observable_value:
            return self._skip(data, "No observable value found")

        # Check if we should enrich this type
        if "ipv4" in entity_type and not self.config.ismalicious.enrich_ipv4:
            return self._skip(data, "IPv4 enrichment disabled")
        if "ipv6" in entity_type and not self.config.ismalicious.enrich_ipv6:
            return self._skip(data, "IPv6 enrichment disabled")
        if "domain" in entity_type and not self.config.ismalicious.enrich_domain:
            return self._skip(data, "Domain enrichment disabled")

        self.helper.log_info(f"Enriching {entity_type}: {observable_value}")

        # Call isMalicious API
        api_data = self._call_api(observable_value)
        if api_data is None:
            return self._skip(data, f"API call failed for {observable_value}")

        # Calculate and set score
        score = self._calculate_score(api_data)
        threshold = self.config.ismalicious.min_score
        if score is None and threshold > 0:
            return self._skip(
                data, "Risk score unavailable; cannot evaluate minimum score, skipping"
            )
        if score is not None:
            if score < threshold:
                return self._skip(data, f"Score {score} below threshold, skipping")
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", score
            )

        # Add labels
        for label in self._get_labels(api_data):
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "labels", label, True
            )

        # Add external references
        for ref in self._get_external_references(api_data, observable_value):
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "external_references", ref, True
            )

        # Add description with summary
        malicious = api_data.get("malicious")
        detections = threat_sources(api_data)
        sources_count = len(detections)
        categories = []
        for source in detections:
            category = source.get("category")
            if category and category not in categories:
                categories.append(category)

        description_parts = []
        if malicious is True:
            status = "malicious"
            description_parts.append(
                f"**Malicious** - Detected by {sources_count} source(s)"
            )
        elif malicious is False:
            status = "not flagged as malicious"
            description_parts.append(
                "Not flagged as malicious by isMalicious; this is not proof of safety."
            )
        else:
            status = "unknown"
            description_parts.append("No malicious verdict available from isMalicious.")
        if score is None:
            description_parts.append(
                "Risk score unavailable; existing OpenCTI score left unchanged."
            )

        if categories:
            description_parts.append(f"Categories: {', '.join(categories)}")

        # What the observable is (cloud, CDN, Tor exit...), apart from the verdict
        infrastructure = api_data.get("infrastructure")
        if isinstance(infrastructure, dict) and infrastructure.get("attributes"):
            attributes = ", ".join(str(a) for a in infrastructure["attributes"])
            description_parts.append(f"Infrastructure: {attributes}")

        # Add reputation summary if available
        if reputation := api_data.get("reputation"):
            rep_parts = []
            for key in ["malicious", "suspicious", "harmless", "undetected"]:
                if count := reputation.get(key, 0):
                    rep_parts.append(f"{key}: {count}")
            if rep_parts:
                description_parts.append(f"Reputation: {', '.join(rep_parts)}")

        description = "\n".join(description_parts)
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity,
            STIX_EXT_OCTI_SCO,
            "x_opencti_description",
            description,
        )

        # Create Location and Sighting from geo data
        if geo := api_data.get("geo"):
            self._create_location_and_sighting(stix_entity, geo, stix_objects)

        # Send enriched data back to OpenCTI
        serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(serialized_bundle)

        score_display = score if score is not None else "unavailable"
        return (
            f"Enrichment complete: {observable_value} is {status} "
            f"(score: {score_display})"
        )

    def run(self) -> None:
        """Start the connector and listen for enrichment requests."""
        self.helper.log_info("Starting isMalicious connector...")
        self.helper.listen(message_callback=self._process_message)
