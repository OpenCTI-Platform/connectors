"""
isMalicious OpenCTI Internal Enrichment Connector

Enriches IP addresses and domains with threat intelligence from isMalicious.com
"""

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

from .models import ConfigLoader


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

# Risk level to score mapping
RISK_LEVEL_SCORES = {
    "critical": 95,
    "high": 80,
    "medium": 60,
    "low": 40,
    "safe": 10,
}


class IsMaliciousConnector:
    """OpenCTI connector for isMalicious threat intelligence."""

    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):
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
            "safe": "#4caf50",  # Green
        }

        for label, color in label_colors.items():
            try:
                self.helper.api.label.read_or_create_unchecked(
                    value=label, color=color
                )
            except Exception as e:
                self.helper.log_warning(f"Could not create label {label}: {e}")

    def _call_api(self, observable_value: str) -> Optional[Dict[str, Any]]:
        """Call isMalicious API to check an observable."""
        try:
            response = requests.get(
                f"{self.api_url}/api/check",
                params={"query": observable_value, "enrichment": "standard"},
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Accept": "application/json",
                },
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"API call failed for {observable_value}: {e}")
            return None

    def _calculate_score(self, data: Dict[str, Any]) -> int:
        """Calculate OpenCTI score (0-100) from isMalicious response."""
        # Check if malicious
        if not data.get("malicious", False):
            return 10  # Low score for non-malicious

        # Use confidence score if available
        if "confidenceScore" in data:
            return min(100, max(0, int(data["confidenceScore"])))

        # Use reputation data if available
        reputation = data.get("reputation", {})
        if reputation:
            malicious = reputation.get("malicious", 0)
            total = sum(
                reputation.get(k, 0)
                for k in ["malicious", "suspicious", "harmless", "undetected"]
            )
            if total > 0:
                # Weight malicious heavily
                score = int((malicious / total) * 100)
                return min(100, max(0, score))

        # Use risk level from metadata
        metadata = data.get("metadata", {})
        threat_level = metadata.get("threatLevel", "medium")
        return RISK_LEVEL_SCORES.get(threat_level, 50)

    def _get_labels(self, data: Dict[str, Any]) -> List[str]:
        """Extract labels from isMalicious response."""
        labels = []

        # Add malicious label if applicable
        if data.get("malicious", False):
            labels.append("malicious")

        # Add category labels
        categories = data.get("categories", [])
        for category in categories:
            if mapped := THREAT_CATEGORY_LABELS.get(category.lower()):
                if mapped not in labels:
                    labels.append(mapped)

        # Also check sources for categories
        for source in data.get("sources", []):
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

        # Add isMalicious reference
        refs.append(
            {
                "source_name": "isMalicious",
                "url": f"https://ismalicious.com/report?query={observable_value}",
                "description": "isMalicious threat intelligence report",
            }
        )

        # Add source references
        for source in data.get("sources", []):
            ref = {
                "source_name": source.get("name", "Unknown"),
            }
            if url := source.get("url"):
                ref["url"] = url
            if category := source.get("category"):
                ref["description"] = f"Detected as: {category}"
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

    def _process_message(self, data: Dict) -> str:
        """Process enrichment request from OpenCTI."""
        opencti_entity = data["enrichment_entity"]
        stix_entity = data["stix_entity"]
        stix_objects = data["stix_objects"]

        # Check TLP
        tlp = "TLP:CLEAR"
        for marking in opencti_entity.get("objectMarking", []):
            if marking.get("definition_type") == "TLP":
                tlp = marking.get("definition", tlp)

        if not OpenCTIConnectorHelper.check_max_tlp(
            tlp, self.config.ismalicious.max_tlp
        ):
            return "TLP too high, skipping enrichment"

        # Get observable value and type
        observable_value = stix_entity.get("value")
        entity_type = opencti_entity.get("entity_type", "").lower()

        if not observable_value:
            return "No observable value found"

        # Check if we should enrich this type
        if "ipv4" in entity_type and not self.config.ismalicious.enrich_ipv4:
            return "IPv4 enrichment disabled"
        if "ipv6" in entity_type and not self.config.ismalicious.enrich_ipv6:
            return "IPv6 enrichment disabled"
        if "domain" in entity_type and not self.config.ismalicious.enrich_domain:
            return "Domain enrichment disabled"

        self.helper.log_info(f"Enriching {entity_type}: {observable_value}")

        # Call isMalicious API
        api_data = self._call_api(observable_value)
        if api_data is None:
            return f"API call failed for {observable_value}"

        # Calculate and set score
        score = self._calculate_score(api_data)
        if score < self.config.ismalicious.min_score_to_report:
            return f"Score {score} below threshold, skipping"

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
        malicious = api_data.get("malicious", False)
        sources_count = len(api_data.get("sources", []))
        categories = api_data.get("categories", [])

        description_parts = []
        if malicious:
            description_parts.append(
                f"**Malicious** - Detected by {sources_count} source(s)"
            )
        else:
            description_parts.append("No threats detected")

        if categories:
            description_parts.append(f"Categories: {', '.join(categories)}")

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

        status = "malicious" if malicious else "clean"
        return f"Enrichment complete: {observable_value} is {status} (score: {score})"

    def run(self) -> None:
        """Start the connector and listen for enrichment requests."""
        self.helper.log_info("Starting isMalicious connector...")
        self.helper.listen(message_callback=self._process_message)
