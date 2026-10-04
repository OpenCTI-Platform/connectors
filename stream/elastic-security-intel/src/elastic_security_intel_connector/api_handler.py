"""
Elastic Security API Handler for threat intelligence and SIEM rules management
"""

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Tuple

import requests
from pycti import OpenCTIConnectorHelper, get_config_variable

READ_BACK_PAGE_SIZE = 500
READ_BACK_KEEP_ALIVE = "2m"
READ_BACK_FIELDS = ["opencti_doc_id", "stix", "threat.indicator.valid_until"]
SIEM_RULE_TYPES = {"eql": "eql", "esql": "esql"}
SIEM_RULE_INDICES = ["logs-*", "filebeat-*", "packetbeat-*", "winlogbeat-*"]
SIEM_RULE_LOOKUP_PAGE_SIZE = 100


def _kql_string(value: str) -> str:
    """Quote a value for a KQL filter."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


class ElasticApiHandlerError(Exception):
    def __init__(self, msg, metadata=None):
        self.msg = msg
        self.metadata = metadata


class ElasticApiHandler:
    """
    Handler for Elastic Security API operations including threat intel and SIEM rules
    """

    def __init__(self, helper: OpenCTIConnectorHelper, config):
        self.helper = helper
        self.config = config
        self.elastic_url = config.elastic_url.rstrip("/")
        self.headers = {
            "Authorization": f"ApiKey {config.elastic_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "kbn-xsrf": "true",  # Required for Kibana API calls
        }
        self.cert = (
            (config.elastic_client_cert, config.elastic_client_key)
            if config.elastic_client_cert and config.elastic_client_key
            else None
        )
        self.verify_ssl = config.elastic_verify_ssl
        self.ca_cert = config.elastic_ca_cert
        self.index_name = config.elastic_index_name

        # Determine OpenCTI URL for reference links ONLY (not for API connections)
        # This is used to build clickable links in Elastic documents that point back to OpenCTI
        if config.elastic_opencti_external_url:
            # Use the explicitly configured external URL (e.g., public-facing URL)
            self.opencti_url = config.elastic_opencti_external_url.rstrip("/")
        else:
            # Fall back to the internal OpenCTI API URL from opencti:url
            self.opencti_url = get_config_variable(
                "OPENCTI_URL",
                ["opencti", "url"],
                config.load,
                default="http://localhost:4000",
            ).rstrip("/")

    def _get_verify_config(self):
        """Get SSL verification configuration"""
        if not self.verify_ssl:
            return False
        if self.ca_cert:
            return self.ca_cert
        return True

    def _get_kibana_url(self):
        """Get Kibana URL for SIEM rule operations"""
        # Use explicitly configured Kibana URL if available
        if (
            hasattr(self.config, "elastic_kibana_url")
            and self.config.elastic_kibana_url
        ):
            return self.config.elastic_kibana_url.rstrip("/")

        # Otherwise, auto-convert from Elasticsearch URL
        kibana_url = self.elastic_url
        if ".es." in kibana_url:
            # Convert from .es. to .kb. for Elastic Cloud
            kibana_url = kibana_url.replace(".es.", ".kb.")
            # Remove port 9243 if present (Elasticsearch port)
            kibana_url = kibana_url.replace(":9243", "")
            # The URL should now be correct with .kb.[region].gcp.cloud.es.io format
            # No further domain manipulation needed

        return kibana_url

    def _generate_doc_id(self, data: dict) -> str:
        """Generate a unique document ID based on OpenCTI ID"""
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        return hashlib.sha256(opencti_id.encode()).hexdigest()

    def document_id(self, data: dict) -> str:
        """Return the opencti_doc_id under which an object is written in the index"""
        return self._generate_doc_id(data)

    def iter_connector_documents(self) -> Iterator[dict]:
        """
        Read back every document written by the connector in the threat intel index.

        A point in time keeps the pages consistent while the stream keeps writing,
        and any error raises: a partial listing would report pushed indicators as removed.

        :return: The ``_source`` of the documents (opencti_doc_id, stix, valid_until)
        :raises ElasticApiHandlerError: On any Elasticsearch error
        """
        verify = self._get_verify_config()
        try:
            opened = requests.post(
                f"{self.elastic_url}/{self.index_name}/_pit",
                headers=self.headers,
                params={"keep_alive": READ_BACK_KEEP_ALIVE},
                verify=verify,
                cert=self.cert,
                timeout=30,
            )
            if opened.status_code == 404:
                # The data stream does not exist yet: nothing has been pushed
                return
            if opened.status_code != 200:
                raise ElasticApiHandlerError(
                    f"Failed to read the indicators back: {opened.status_code}",
                    {"response": opened.text[:500]},
                )
            pit_id = opened.json()["id"]
            try:
                search_after = None
                while True:
                    body: Dict[str, Any] = {
                        "size": READ_BACK_PAGE_SIZE,
                        "query": {"exists": {"field": "opencti_doc_id"}},
                        "_source": READ_BACK_FIELDS,
                        "pit": {"id": pit_id, "keep_alive": READ_BACK_KEEP_ALIVE},
                        "sort": [{"_shard_doc": "asc"}],
                    }
                    if search_after is not None:
                        body["search_after"] = search_after
                    response = requests.post(
                        f"{self.elastic_url}/_search",
                        headers=self.headers,
                        json=body,
                        verify=verify,
                        cert=self.cert,
                        timeout=60,
                    )
                    if response.status_code != 200:
                        raise ElasticApiHandlerError(
                            f"Failed to read the indicators back: {response.status_code}",
                            {"response": response.text[:500]},
                        )
                    result = response.json()
                    hits_block = (
                        result.get("hits") if isinstance(result, dict) else None
                    )
                    hits = (
                        hits_block.get("hits") if isinstance(hits_block, dict) else None
                    )
                    if not isinstance(hits, list):
                        # Never read as an empty page: every deployment would look absent.
                        raise ElasticApiHandlerError(
                            "Failed to read the indicators back: unexpected search response",
                            {"response": response.text[:500]},
                        )
                    pit_id = result.get("pit_id", pit_id)
                    for hit in hits:
                        source = hit.get("_source") if isinstance(hit, dict) else None
                        if not isinstance(source, dict):
                            # Never skipped: its deployment would look absent.
                            raise ElasticApiHandlerError(
                                "Failed to read the indicators back: a hit carries no document",
                                {"response": response.text[:500]},
                            )
                        yield source
                    if len(hits) < READ_BACK_PAGE_SIZE:
                        return
                    last = hits[-1]
                    search_after = last.get("sort") if isinstance(last, dict) else None
                    if not search_after:
                        # Without a cursor the next request would read the first page again forever.
                        raise ElasticApiHandlerError(
                            "Failed to read the indicators back: a full page carries no sort cursor",
                            {"response": response.text[:500]},
                        )
            finally:
                try:
                    requests.delete(
                        f"{self.elastic_url}/_pit",
                        headers=self.headers,
                        json={"id": pit_id},
                        verify=verify,
                        cert=self.cert,
                        timeout=30,
                    )
                except requests.exceptions.RequestException:
                    # The point in time expires on its own
                    pass
        except requests.exceptions.RequestException as e:
            raise ElasticApiHandlerError(
                "Request failed while reading the indicators back", {"error": str(e)}
            )

    def _is_elastic_native_pattern(self, pattern_type: str) -> bool:
        """
        Check if the pattern type is native to Elastic

        :param pattern_type: Type of pattern
        :return: True if native Elastic pattern type
        """
        return pattern_type in ["kql", "lucene", "eql", "esql"]

    def _convert_elastic_pattern_to_query(
        self, pattern: str, pattern_type: str
    ) -> Dict[str, Any]:
        """
        Convert Elastic native pattern to query configuration

        :param pattern: The pattern string
        :param pattern_type: Type of pattern (kql, lucene, eql, esql)
        :return: Dictionary with query configuration for Elastic rule
        """
        query_config = {}

        if pattern_type == "kql":
            query_config["language"] = "kuery"
            query_config["query"] = pattern

        elif pattern_type == "lucene":
            query_config["language"] = "lucene"
            query_config["query"] = pattern

        elif pattern_type == "eql":
            query_config["language"] = "eql"
            query_config["query"] = pattern

        elif pattern_type == "esql":
            # ES|QL is a special case
            query_config["language"] = "esql"
            query_config["query"] = pattern

        return query_config

    def _create_siem_rule(self, indicator_data: dict) -> Optional[dict]:
        """
        Create a SIEM detection rule from a STIX indicator with native Elastic pattern

        :param indicator_data: STIX indicator data with pattern
        :return: Created rule data or None
        """
        try:
            opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", indicator_data
            )
            pattern = indicator_data.get("pattern", "")
            pattern_type = indicator_data.get("pattern_type", "stix")

            # Only create SIEM rules for native Elastic patterns
            if not self._is_elastic_native_pattern(pattern_type):
                self.helper.connector_logger.debug(
                    f"Skipping SIEM rule creation for non-native pattern type: {pattern_type}",
                    {"opencti_id": opencti_id},
                )
                return None

            # Convert pattern to Elastic query
            query_config = self._convert_elastic_pattern_to_query(pattern, pattern_type)

            # Build the rule
            rule_type = SIEM_RULE_TYPES.get(pattern_type, "query")
            rule = {
                "name": f"OpenCTI: {indicator_data.get('name', 'Threat Indicator')}",
                "description": indicator_data.get(
                    "description", "Rule created from OpenCTI threat indicator"
                ),
                "risk_score": self._calculate_risk_score(indicator_data),
                "severity": self._get_severity(indicator_data),
                "type": rule_type,
                "query": query_config["query"],
                "language": query_config["language"],
                "interval": "5m",
                "from": "now-6m",
                "enabled": True,
                "tags": ["opencti", "threat-intel"],
                "references": [self._rule_reference(opencti_id)],
                "meta": {
                    "opencti_id": opencti_id,
                    "pattern_type": pattern_type,
                    "original_pattern": pattern,
                },
            }
            if rule_type != "esql":
                # ES|QL rules read the indices named in their query
                rule["index"] = list(SIEM_RULE_INDICES)

            # Add threat mapping if available
            if "kill_chain_phases" in indicator_data:
                threat_mapping = self._build_threat_mapping(indicator_data)
                if threat_mapping:
                    rule["threat"] = threat_mapping

            # Add labels as tags
            if "labels" in indicator_data:
                rule["tags"].extend(indicator_data["labels"])

            # Create the rule via Kibana API
            kibana_url = self._get_kibana_url()
            url = f"{kibana_url}/api/detection_engine/rules"

            response = requests.post(
                url,
                headers=self.headers,  # Already includes kbn-xsrf header
                json=rule,
                verify=self._get_verify_config(),
                cert=self.cert,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                self.helper.connector_logger.info(
                    "Created SIEM rule from indicator",
                    {"rule_id": result.get("id"), "opencti_id": opencti_id},
                )
                return result
            else:
                self.helper.connector_logger.warning(
                    f"Failed to create SIEM rule: {response.status_code}",
                    {"response": response.text, "opencti_id": opencti_id},
                )
                return None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error creating SIEM rule: {str(e)}", {"indicator_id": opencti_id}
            )
            return None

    def _update_siem_rule(self, indicator_data: dict, rule_id: str) -> Optional[dict]:
        """Update the fields of an existing SIEM rule derived from the indicator.

        A partial update (PATCH): the indices, schedule, tags and references of
        the rule are kept.
        """
        try:
            opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", indicator_data
            )
            pattern = indicator_data.get("pattern", "")
            pattern_type = indicator_data.get("pattern_type", "stix")

            # Only update SIEM rules for native Elastic patterns
            if not self._is_elastic_native_pattern(pattern_type):
                self.helper.connector_logger.debug(
                    f"Skipping SIEM rule update for non-native pattern type: {pattern_type}",
                    {"opencti_id": opencti_id},
                )
                return None

            # Convert pattern to Elastic query
            query_config = self._convert_elastic_pattern_to_query(pattern, pattern_type)

            # Build the update
            rule_update = {
                "id": rule_id,
                "name": f"OpenCTI: {indicator_data.get('name', 'Threat Indicator')}",
                "description": indicator_data.get(
                    "description", "Rule created from OpenCTI threat indicator"
                ),
                "risk_score": self._calculate_risk_score(indicator_data),
                "severity": self._get_severity(indicator_data),
                "query": query_config["query"],
                "language": query_config["language"],
            }

            # Update the rule via Kibana API
            kibana_url = self._get_kibana_url()
            url = f"{kibana_url}/api/detection_engine/rules"

            response = requests.patch(
                url,
                headers=self.headers,
                json=rule_update,
                verify=self._get_verify_config(),
                cert=self.cert,
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()
                self.helper.connector_logger.info(
                    "Updated SIEM rule from indicator",
                    {"rule_id": rule_id, "opencti_id": opencti_id},
                )
                return result
            else:
                self.helper.connector_logger.warning(
                    f"Failed to update SIEM rule: {response.status_code}",
                    {"response": response.text, "opencti_id": opencti_id},
                )
                return None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error updating SIEM rule: {str(e)}", {"indicator_id": opencti_id}
            )
            return None

    def _delete_siem_rule(self, rule_id: str) -> bool:
        """Delete a SIEM rule"""
        try:
            # For SIEM rules, we need to use Kibana URL, not Elasticsearch
            kibana_url = self._get_kibana_url()
            url = f"{kibana_url}/api/detection_engine/rules"
            params = {"id": rule_id}

            response = requests.delete(
                url,
                headers=self.headers,
                params=params,
                verify=self._get_verify_config(),
                cert=self.cert,
                timeout=30,
            )

            if response.status_code in [200, 404]:  # 404 is ok, already deleted
                self.helper.connector_logger.info(
                    "Deleted SIEM rule", {"rule_id": rule_id}
                )
                return True
            else:
                self.helper.connector_logger.warning(
                    f"Failed to delete SIEM rule: {response.status_code}",
                    {"response": response.text},
                )
                return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error deleting SIEM rule: {str(e)}", {"rule_id": rule_id}
            )
            return False

    def _rule_reference(self, opencti_id: str) -> str:
        """Return the reference a SIEM rule carries to its OpenCTI indicator."""
        return f"{self.opencti_url}/dashboard/id/{opencti_id}"

    def _find_siem_rule_ids(self, opencti_id: str) -> List[str]:
        """Find the SIEM rules created from an indicator.

        Rule parameters are stored under ``alert.attributes.params``: a rule is
        matched by the indicator reference it was created with, or by the
        ``meta.opencti_id`` it carries until the rule is edited in Kibana.

        :param opencti_id: OpenCTI ID of the indicator
        :return: The ids of the rules, every page read
        :raises Exception: When Kibana cannot be queried (the rules are unknown)
        """
        # The detection engine is a Kibana API, like the other SIEM rule calls
        url = f"{self._get_kibana_url()}/api/detection_engine/rules/_find"
        rule_filter = (
            "alert.attributes.params.references:"
            f"{_kql_string(self._rule_reference(opencti_id))}"
            " or alert.attributes.params.meta.opencti_id:"
            f"{_kql_string(opencti_id)}"
        )
        rule_ids: List[str] = []
        page = 1
        while True:
            response = requests.get(
                url,
                headers=self.headers,
                params={
                    "filter": rule_filter,
                    "page": page,
                    "per_page": SIEM_RULE_LOOKUP_PAGE_SIZE,
                },
                verify=self._get_verify_config(),
                cert=self.cert,
                timeout=30,
            )
            response.raise_for_status()
            body = response.json()
            rules = body.get("data") or []
            rule_ids.extend(str(rule["id"]) for rule in rules)
            if not rules or len(rule_ids) >= int(body.get("total") or 0):
                return rule_ids
            page += 1

    def _lookup_siem_rule_ids(self, opencti_id: str) -> Optional[List[str]]:
        """Find the SIEM rules of an indicator, logging a failed lookup.

        :param opencti_id: OpenCTI ID of the indicator
        :return: The ids of the rules, None when the lookup failed
        """
        try:
            return self._find_siem_rule_ids(opencti_id)
        except Exception as e:
            self.helper.connector_logger.warning(
                "Cannot look up the SIEM rule of the indicator",
                meta={"opencti_id": opencti_id, "error": str(e)},
            )
            return None

    def _write_siem_rules_of_indicator(
        self, indicator_data: dict, opencti_id: str
    ) -> Tuple[bool, Optional[str]]:
        """Update the SIEM rules created from an indicator, or create its rule.

        Looking the rules up first keeps a replayed or pushed again indicator
        from creating a second rule.

        :param indicator_data: STIX indicator data with a native Elastic pattern
        :param opencti_id: OpenCTI ID of the indicator
        :return: False when the rule lookup, creation or an update failed, and
            the id of the rule created (None when existing rules were updated)
        """
        rule_ids = self._lookup_siem_rule_ids(opencti_id)
        if rule_ids is None:
            return False, None
        if not rule_ids:
            rule = self._create_siem_rule(indicator_data)
            if rule is None:
                return False, None
            return True, str(rule["id"]) if rule.get("id") else None
        updated = all(
            [
                self._update_siem_rule(indicator_data, rule_id) is not None
                for rule_id in rule_ids
            ]
        )
        return updated, None

    def _roll_back_siem_rule(self, rule_id: str, opencti_id: str) -> None:
        """Delete a rule created for a threat intel entry that was not written.

        :param rule_id: ID of the rule created
        :param opencti_id: OpenCTI ID of the indicator
        """
        if self._delete_siem_rule(rule_id):
            return
        self.helper.connector_logger.error(
            "SIEM rule created without its threat intel entry not deleted, "
            "the next event or push of the indicator updates or deletes it",
            meta={"rule_id": rule_id, "opencti_id": opencti_id},
        )

    def _delete_siem_rule_of_indicator(self, opencti_id: str) -> bool:
        """Delete the SIEM rules created from an indicator, if it has any.

        :param opencti_id: OpenCTI ID of the indicator
        :return: False when the rule lookup or a deletion failed (a rule may remain)
        """
        rule_ids = self._lookup_siem_rule_ids(opencti_id)
        if rule_ids is None:
            return False
        return all([self._delete_siem_rule(rule_id) for rule_id in rule_ids])

    def _calculate_risk_score(self, indicator_data: dict) -> int:
        """Calculate risk score based on indicator confidence and severity"""
        confidence = indicator_data.get("confidence", 50)
        # Map confidence (0-100) to risk score (0-100)
        return min(100, max(1, confidence))

    def _get_severity(self, indicator_data: dict) -> str:
        """Get severity level for the rule"""
        confidence = indicator_data.get("confidence", 50)

        if confidence >= 80:
            return "critical"
        elif confidence >= 60:
            return "high"
        elif confidence >= 40:
            return "medium"
        else:
            return "low"

    def _build_threat_mapping(self, indicator_data: dict) -> List[dict]:
        """Build MITRE ATT&CK threat mapping from kill chain phases"""
        threat_mapping = []

        for phase in indicator_data.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name", "")

                # Parse technique ID if present
                if phase_name.startswith("T"):
                    technique_id = phase_name.split(".")[0]
                    threat_entry = {
                        "framework": "MITRE ATT&CK",
                        "technique": [
                            {
                                "id": technique_id,
                                "name": phase_name,
                                "reference": f"https://attack.mitre.org/techniques/{technique_id}/",
                            }
                        ],
                    }

                    # Add subtechnique if present
                    if "." in phase_name:
                        subtechnique_id = phase_name
                        threat_entry["technique"][0]["subtechnique"] = [
                            {
                                "id": subtechnique_id,
                                "name": subtechnique_id,
                                "reference": f"https://attack.mitre.org/techniques/{subtechnique_id.replace('.', '/')}/",
                            }
                        ]

                    threat_mapping.append(threat_entry)

        return threat_mapping

    def _convert_to_ecs_threat(self, observable_data: dict) -> dict:
        """
        Convert OpenCTI observable/indicator to strictly ECS-compliant threat format
        Following: https://www.elastic.co/docs/reference/ecs/ecs-threat
        """
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", observable_data
        )
        created = observable_data.get("created", datetime.utcnow().isoformat())
        modified = observable_data.get("modified", datetime.utcnow().isoformat())

        # Check if this is a pattern-based indicator
        is_pattern_indicator = "pattern" in observable_data

        # Get the indicator value and name
        if is_pattern_indicator:
            indicator_value = observable_data.get("pattern", "")
            # For patterns, use name or truncated pattern
            indicator_name = observable_data.get(
                "name",
                (
                    indicator_value[:100]
                    if len(indicator_value) > 100
                    else indicator_value
                ),
            )
        else:
            indicator_value = observable_data.get("value", "")
            indicator_name = observable_data.get("name", indicator_value)

        # Strictly ECS-compliant document structure with Fleet metadata
        ecs_doc = {
            "@timestamp": datetime.utcnow().isoformat(),
            "event": {
                "kind": "enrichment",
                "category": ["threat"],
                "type": ["indicator"],
                "created": created,
                "module": "ti_opencti",
                "dataset": "ti_opencti.indicator",
                "ingested": datetime.utcnow().isoformat(),
            },
            "threat": {"indicator": {}},
            # Add data_stream metadata required by Threat Intelligence UI
            "data_stream": {
                "dataset": "ti_opencti.indicator",
                "namespace": "default",
                "type": "logs",
            },
        }

        # Core threat.indicator fields (ECS compliant)
        threat_indicator = ecs_doc["threat"]["indicator"]

        # Required/Core fields
        threat_indicator["type"] = "unknown"  # Will be set based on type

        # Extended fields (all from ECS threat specification)
        if indicator_name:
            threat_indicator["name"] = indicator_name
        if observable_data.get("description"):
            threat_indicator["description"] = observable_data.get("description")

        # Confidence - use numeric value as expected by Elastic
        confidence = observable_data.get("confidence", 0)
        threat_indicator["confidence"] = confidence

        # Temporal fields
        threat_indicator["first_seen"] = created
        threat_indicator["last_seen"] = modified
        threat_indicator["modified_at"] = modified

        # Sightings (using OpenCTI score if available)
        if "x_opencti_score" in observable_data:
            threat_indicator["sightings"] = observable_data["x_opencti_score"]

        # Reference (OpenCTI source) - use proper URL format with /id/{ID}
        threat_indicator["reference"] = f"{self.opencti_url}/dashboard/id/{opencti_id}"
        threat_indicator["provider"] = ["OpenCTI"]  # ECS expects array

        # Feed information
        ecs_doc["threat"]["feed"] = {
            "name": "OpenCTI",
            "reference": "https://github.com/OpenCTI-Platform/opencti",
        }

        # TLP marking (ECS field: threat.indicator.marking.tlp)
        tlp_marking = "WHITE"  # Default
        if "objectMarking" in observable_data:
            for marking in observable_data.get("objectMarking", []):
                definition = marking.get("definition", "")
                if "TLP:" in definition.upper():
                    tlp_marking = definition.upper().replace("TLP:", "").strip()

        threat_indicator["marking"] = {"tlp": tlp_marking}

        # Handle pattern-based indicators
        if is_pattern_indicator:
            # For pattern-based indicators, set type based on pattern type
            pattern_type = observable_data.get("pattern_type", "stix")
            pattern = observable_data.get("pattern", "")

            # Parse STIX pattern to extract type and value
            if pattern_type == "stix" and pattern:
                # Extract value from STIX pattern using regex
                import re

                # Pattern to extract IPv4 addresses
                ipv4_match = re.search(
                    r"\[ipv4-addr:value\s*=\s*['\"]([^'\"]+)['\"]", pattern
                )
                if ipv4_match:
                    ip_value = ipv4_match.group(1)
                    threat_indicator["type"] = "ipv4-addr"
                    threat_indicator["ip"] = [ip_value]  # ECS expects array
                    if not threat_indicator.get("name"):
                        threat_indicator["name"] = ip_value
                    # Add to related fields for correlation
                    ecs_doc["related"] = {"ip": [ip_value]}

                # Pattern to extract IPv6 addresses
                elif re.search(r"\[ipv6-addr:value\s*=\s*['\"]", pattern):
                    ipv6_match = re.search(
                        r"\[ipv6-addr:value\s*=\s*['\"]([^'\"]+)['\"]", pattern
                    )
                    if ipv6_match:
                        ip_value = ipv6_match.group(1)
                        threat_indicator["type"] = "ipv6-addr"
                        threat_indicator["ip"] = [ip_value]  # ECS expects array
                        if not threat_indicator.get("name"):
                            threat_indicator["name"] = ip_value
                        # Add to related fields for correlation
                        ecs_doc["related"] = {"ip": [ip_value]}

                # Pattern to extract domains
                elif re.search(r"\[(domain-name|domain):value\s*=\s*['\"]", pattern):
                    domain_match = re.search(
                        r"\[(domain-name|domain):value\s*=\s*['\"]([^'\"]+)['\"]",
                        pattern,
                    )
                    if domain_match:
                        domain_value = domain_match.group(2)
                        threat_indicator["type"] = "domain-name"
                        threat_indicator["url"] = {"domain": domain_value}
                        if not threat_indicator.get("name"):
                            threat_indicator["name"] = domain_value
                        ecs_doc.setdefault("related", {})["hosts"] = [domain_value]

                # Pattern to extract URLs
                elif re.search(r"\[url:value\s*=\s*['\"]", pattern):
                    url_match = re.search(
                        r"\[url:value\s*=\s*['\"]([^'\"]+)['\"]", pattern
                    )
                    if url_match:
                        url_value = url_match.group(1)
                        threat_indicator["type"] = "url"
                        if not threat_indicator.get("name"):
                            threat_indicator["name"] = url_value

                        # Parse URL according to ECS specification
                        from urllib.parse import urlparse

                        try:
                            parsed = urlparse(url_value)
                            url_dict = {"original": url_value, "full": url_value}
                            if parsed.scheme:
                                url_dict["scheme"] = parsed.scheme
                            if parsed.hostname:
                                url_dict["domain"] = parsed.hostname
                            if parsed.port:
                                url_dict["port"] = parsed.port
                            if parsed.path:
                                url_dict["path"] = parsed.path
                            if parsed.query:
                                url_dict["query"] = parsed.query
                            if parsed.fragment:
                                url_dict["fragment"] = parsed.fragment

                            threat_indicator["url"] = url_dict
                            # Add domain to related hosts if extracted
                            if parsed.hostname:
                                ecs_doc.setdefault("related", {})["hosts"] = [
                                    parsed.hostname
                                ]
                        except (ValueError, AttributeError) as e:
                            self.helper.connector_logger.debug(
                                f"Could not parse URL '{url_value}': {str(e)}"
                            )
                            threat_indicator["url"] = {
                                "original": url_value,
                                "full": url_value,
                            }

                # Pattern to extract email addresses
                elif re.search(r"\[email-addr:value\s*=\s*['\"]", pattern):
                    email_match = re.search(
                        r"\[email-addr:value\s*=\s*['\"]([^'\"]+)['\"]", pattern
                    )
                    if email_match:
                        email_value = email_match.group(1)
                        threat_indicator["type"] = "email-addr"
                        threat_indicator["email"] = {"address": email_value}
                        if not threat_indicator.get("name"):
                            threat_indicator["name"] = email_value
                        # Add to related fields
                        ecs_doc.setdefault("related", {})["user"] = [email_value]

                # Pattern to extract file hashes
                elif re.search(r"\[file:hashes\.", pattern):
                    threat_indicator["type"] = "file"
                    file_hashes = {}

                    # Extract MD5
                    md5_match = re.search(
                        r"hashes\.MD5\s*=\s*['\"]([^'\"]+)['\"]", pattern
                    )
                    if md5_match:
                        file_hashes["md5"] = md5_match.group(1)

                    # Extract SHA1
                    sha1_match = re.search(
                        r"hashes\.(SHA1|'SHA-1')\s*=\s*['\"]([^'\"]+)['\"]", pattern
                    )
                    if sha1_match:
                        file_hashes["sha1"] = sha1_match.group(2)

                    # Extract SHA256
                    sha256_match = re.search(
                        r"hashes\.(SHA256|'SHA-256')\s*=\s*['\"]([^'\"]+)['\"]", pattern
                    )
                    if sha256_match:
                        file_hashes["sha256"] = sha256_match.group(2)

                    if file_hashes:
                        threat_indicator["file"] = {"hash": file_hashes}
                        # Use first available hash as name
                        hash_name = (
                            file_hashes.get("sha256")
                            or file_hashes.get("sha1")
                            or file_hashes.get("md5")
                        )
                        if hash_name and not threat_indicator.get("name"):
                            threat_indicator["name"] = hash_name
                        # Add to related fields for correlation
                        related_hashes = []
                        for hash_value in file_hashes.values():
                            if hash_value:
                                related_hashes.append(hash_value)
                        if related_hashes:
                            ecs_doc.setdefault("related", {})["hash"] = related_hashes
            elif pattern_type in ["kql", "lucene", "eql", "esql"]:
                # For Elastic-native pattern types, store as query
                threat_indicator["type"] = "query"
                threat_indicator["query"] = pattern
        else:
            # Handle observables (non-pattern indicators)
            obs_type = observable_data.get("type", "").lower()
            obs_value = observable_data.get("value", "")

            # Set name if not already set
            if not threat_indicator.get("name"):
                threat_indicator["name"] = obs_value

            # Map indicator types and values according to ECS threat intelligence spec
            if obs_type == "ipv4-addr":
                threat_indicator["type"] = "ipv4-addr"
                threat_indicator["ip"] = [obs_value]  # ECS expects array
                ecs_doc["related"] = {"ip": [obs_value]}

            elif obs_type == "ipv6-addr":
                threat_indicator["type"] = "ipv6-addr"
                threat_indicator["ip"] = [obs_value]  # ECS expects array
                ecs_doc["related"] = {"ip": [obs_value]}

            elif obs_type == "domain-name" or obs_type == "domain":
                threat_indicator["type"] = "domain-name"
                threat_indicator["url"] = {"domain": obs_value}
                ecs_doc["related"] = {"hosts": [obs_value]}

            elif obs_type == "url":
                threat_indicator["type"] = "url"
                # Parse URL according to ECS specification
                from urllib.parse import urlparse

                try:
                    parsed = urlparse(obs_value)
                    url_dict = {"original": obs_value, "full": obs_value}
                    if parsed.scheme:
                        url_dict["scheme"] = parsed.scheme
                    if parsed.hostname:
                        url_dict["domain"] = parsed.hostname
                    if parsed.port:
                        url_dict["port"] = parsed.port
                    if parsed.path:
                        url_dict["path"] = parsed.path
                    if parsed.query:
                        url_dict["query"] = parsed.query
                    if parsed.fragment:
                        url_dict["fragment"] = parsed.fragment

                    threat_indicator["url"] = url_dict
                    # Add domain to related hosts if extracted
                    if parsed.hostname:
                        ecs_doc.setdefault("related", {})["hosts"] = [parsed.hostname]
                except (ValueError, AttributeError) as e:
                    self.helper.connector_logger.debug(
                        f"Could not parse URL '{obs_value}': {str(e)}"
                    )
                    threat_indicator["url"] = {"original": obs_value, "full": obs_value}

            elif obs_type == "email-addr" or obs_type == "email-address":
                threat_indicator["type"] = "email-addr"
                threat_indicator["email"] = {"address": obs_value}
                # Add to related fields
                ecs_doc.setdefault("related", {})["user"] = [obs_value]

            elif obs_type == "file":
                threat_indicator["type"] = "file"
                hashes = observable_data.get("hashes", {})
                file_hash = {}
                # Store the primary hash value as the name if not already set
                primary_hash = None
                if "SHA-256" in hashes:
                    file_hash["sha256"] = hashes["SHA-256"]
                    primary_hash = hashes["SHA-256"]
                if "SHA-1" in hashes:
                    file_hash["sha1"] = hashes["SHA-1"]
                    if not primary_hash:
                        primary_hash = hashes["SHA-1"]
                if "MD5" in hashes:
                    file_hash["md5"] = hashes["MD5"]
                    if not primary_hash:
                        primary_hash = hashes["MD5"]

                if file_hash:
                    threat_indicator["file"] = {"hash": file_hash}
                    # Use the hash as the name for file indicators
                    if primary_hash and not threat_indicator.get("name"):
                        threat_indicator["name"] = primary_hash
                    # Add to related fields for correlation
                    related_hashes = []
                    for hash_value in file_hash.values():
                        if hash_value:
                            related_hashes.append(hash_value)
                    if related_hashes:
                        ecs_doc.setdefault("related", {})["hash"] = related_hashes

            elif obs_type == "autonomous-system":
                threat_indicator["type"] = "autonomous-system"
                # Extract AS number
                as_number = obs_value
                if as_number.upper().startswith("AS"):
                    as_number = as_number[2:]
                try:
                    threat_indicator["as"] = {
                        "number": int(as_number),
                        "organization": {
                            "name": observable_data.get("name", f"AS{as_number}")
                        },
                    }
                except (ValueError, TypeError) as e:
                    self.helper.connector_logger.debug(
                        f"Could not parse AS number '{as_number}': {str(e)}"
                    )

            elif obs_type == "mac-addr":
                threat_indicator["type"] = "mac-addr"
                threat_indicator["mac"] = obs_value

            elif obs_type == "windows-registry-key":
                threat_indicator["type"] = "windows-registry-key"
                threat_indicator["registry"] = {"key": obs_value, "path": obs_value}

            elif obs_type == "x509-certificate":
                threat_indicator["type"] = "x509-certificate"
                x509_data = observable_data.get("x509", {})
                if x509_data:
                    threat_indicator["x509"] = x509_data

            else:
                # For unknown types, still set the type
                threat_indicator["type"] = obs_type

            # Add port information if available (for network observables)
            if "port" in observable_data:
                threat_indicator["port"] = observable_data["port"]

        # Add valid_from and valid_until if available (ECS threat fields)
        if "valid_from" in observable_data:
            threat_indicator["valid_from"] = observable_data["valid_from"]
        if "valid_until" in observable_data:
            threat_indicator["valid_until"] = observable_data["valid_until"]

        # Add the raw STIX source as a separate field for reference
        ecs_doc["stix"] = observable_data

        return ecs_doc

    def _get_tlp_marking(self, observable_data: dict) -> str:
        """Extract TLP marking from observable data"""
        for marking in observable_data.get("objectMarking", []):
            definition = marking.get("definition", "").upper()
            if definition.startswith("TLP:"):
                return definition.replace("TLP:", "").lower()
        return "white"  # Default to TLP:WHITE

    def process_indicator(self, indicator_data: dict, operation: str) -> bool:
        """
        Process a STIX indicator - create threat intel and optionally SIEM rule for native patterns

        :param indicator_data: STIX indicator data
        :param operation: Operation type (create, update, delete)
        :return: Success status
        """
        success = True
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
            "id", indicator_data
        )
        pattern_type = indicator_data.get("pattern_type", "stix")
        created_rule_id: Optional[str] = None

        try:
            # Handle pattern-based indicators as SIEM rules only if native Elastic pattern
            if "pattern" in indicator_data and self._is_elastic_native_pattern(
                pattern_type
            ):
                if operation in ("create", "update"):
                    written, created_rule_id = self._write_siem_rules_of_indicator(
                        indicator_data, opencti_id
                    )
                    if not written:
                        # The threat intel document is the trace the deployment
                        # read-back sees: it is only written once the rule is.
                        self.helper.connector_logger.warning(
                            "SIEM rule of the indicator not written, threat intel entry not written",
                            meta={"opencti_id": opencti_id, "operation": operation},
                        )
                        return False

                elif operation == "delete":
                    if not self._delete_siem_rule_of_indicator(opencti_id):
                        # The threat intel document is the trace the deployment
                        # read-back sees: it stays while the rule may remain, so
                        # the next removal retries the rule cleanup.
                        self.helper.connector_logger.warning(
                            "SIEM rule of the indicator not removed, threat intel entry kept",
                            meta={"opencti_id": opencti_id},
                        )
                        return False

            if operation in ("create", "update"):
                written_document = False
                try:
                    write = (
                        self.create_indicator
                        if operation == "create"
                        else self.update_indicator
                    )
                    written_document = bool(write(indicator_data))
                finally:
                    # A rule without its threat intel entry would detect unseen
                    # by the deployment read-back.
                    if not written_document and created_rule_id is not None:
                        self._roll_back_siem_rule(created_rule_id, opencti_id)
                if not written_document:
                    success = False
                else:
                    self.helper.connector_logger.info(
                        f"Wrote threat intel entry for {pattern_type} indicator",
                        meta={"opencti_id": opencti_id, "operation": operation},
                    )
            elif operation == "delete":
                if not self.delete_indicator(indicator_data):
                    success = False
                else:
                    self.helper.connector_logger.info(
                        f"Deleted threat intel entry for {pattern_type} indicator",
                        {"opencti_id": opencti_id},
                    )

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error processing indicator: {str(e)}",
                {"opencti_id": opencti_id, "operation": operation},
            )
            success = False

        return success

    def _delete_docs_by_opencti_id(
        self, doc_id: str, keep: Optional[str] = None
    ) -> int:
        """
        Delete every document matching the given opencti_doc_id from the data stream.

        Data streams auto-generate document IDs, so deduplication can only be done by
        query. ``conflicts=proceed`` prevents version conflicts from aborting the
        deletion and leaving stale duplicates behind.

        :param doc_id: The opencti_doc_id shared by the documents to remove
        :param keep: The ``_id`` of a document to keep (the one just written)
        :return: Number of documents deleted
        """
        delete_query: Dict[str, Any] = {"query": {"term": {"opencti_doc_id": doc_id}}}
        if keep is not None:
            delete_query = {
                "query": {
                    "bool": {
                        "filter": [{"term": {"opencti_doc_id": doc_id}}],
                        "must_not": [{"ids": {"values": [keep]}}],
                    }
                }
            }
        url = f"{self.elastic_url}/{self.index_name}/_delete_by_query"
        response = requests.post(
            url,
            headers=self.headers,
            params={"conflicts": "proceed"},
            json=delete_query,
            verify=self._get_verify_config(),
            cert=self.cert,
            timeout=30,
        )

        if response.status_code in [200, 404]:  # 404 is ok, index/doc not there yet
            result = response.json() if response.status_code == 200 else {}
            return result.get("deleted", 0)

        raise ElasticApiHandlerError(
            f"Failed to delete indicator(s): {response.status_code}",
            {"response": response.text},
        )

    def _replace_document(self, observable_data: dict, action: str) -> dict:
        """Write the document of an object, then delete its previous documents.

        Data streams are append-only and auto-generate document IDs: the new
        document is stored first, so a failed write keeps the previous one, and
        the other documents of the object are deleted once it is stored. A
        failed cleanup leaves duplicates that the next write of the object
        deletes; the object is written either way.

        :param observable_data: The STIX object
        :param action: ``create`` or ``update``, for the logs and errors
        :return: The ``_id`` of the new document, its opencti_doc_id and the response
        :raises ElasticApiHandlerError: When the document is not written
        """
        doc_id = self._generate_doc_id(observable_data)
        ecs_doc = self._convert_to_ecs_threat(observable_data)

        # Add document ID as a field for reference (since data streams auto-generate IDs)
        ecs_doc["opencti_doc_id"] = doc_id

        try:
            response = requests.post(
                f"{self.elastic_url}/{self.index_name}/_doc",
                headers=self.headers,
                json=ecs_doc,
                verify=self._get_verify_config(),
                cert=self.cert,
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            raise ElasticApiHandlerError(
                f"Request failed while trying to {action} indicator", {"error": str(e)}
            )
        if response.status_code not in [200, 201]:
            raise ElasticApiHandlerError(
                f"Failed to {action} indicator: {response.status_code}",
                {"response": response.text},
            )
        result = response.json()
        elastic_id = result.get("_id")

        if elastic_id:
            try:
                deleted = self._delete_docs_by_opencti_id(doc_id, keep=elastic_id)
                self.helper.connector_logger.debug(
                    f"Deleted {deleted} previous indicator document(s)",
                    meta={"opencti_doc_id": doc_id},
                )
            except (ElasticApiHandlerError, requests.exceptions.RequestException) as e:
                self.helper.connector_logger.warning(
                    "Previous threat intel entries not removed, removed with the next write",
                    meta={"opencti_doc_id": doc_id, "error": str(e)},
                )
        self.helper.connector_logger.debug(
            f"Successfully wrote indicator in Elastic ({action})",
            meta={
                "elastic_id": elastic_id,
                "opencti_doc_id": doc_id,
                "result": result.get("result"),
            },
        )
        return {"id": elastic_id, "opencti_doc_id": doc_id, "result": result}

    def create_indicator(self, observable_data: dict) -> Optional[dict]:
        """Create a threat indicator in Elastic Security.

        A replayed create replaces the existing document instead of adding a copy.
        """
        return self._replace_document(observable_data, "create")

    def bulk_create_indicators(self, observables_data: List[dict]) -> dict:
        """
        Bulk create threat indicators in Elastic Security using the _bulk API

        :param observables_data: List of observable data dictionaries
        :return: Dictionary with creation statistics and any errors
        """
        try:
            # Build bulk request body
            bulk_body = []
            doc_ids = []

            for observable_data in observables_data:
                doc_id = self._generate_doc_id(observable_data)
                ecs_doc = self._convert_to_ecs_threat(observable_data)

                # Add document ID as a field for reference
                ecs_doc["opencti_doc_id"] = doc_id
                doc_ids.append(doc_id)

                # Add index action for bulk API
                # For data streams, we use "create" action to ensure documents aren't overwritten
                bulk_body.append({"create": {"_index": self.index_name}})
                bulk_body.append(ecs_doc)

            # Convert to newline-delimited JSON format required by _bulk API
            bulk_data = "\n".join([json.dumps(item) for item in bulk_body]) + "\n"

            # Use _bulk API
            url = f"{self.elastic_url}/_bulk"
            response = requests.post(
                url,
                headers={**self.headers, "Content-Type": "application/x-ndjson"},
                data=bulk_data,
                verify=self._get_verify_config(),
                cert=self.cert,
                timeout=60,  # Longer timeout for bulk operations
            )

            if response.status_code in [200, 201]:
                result = response.json()

                # Process bulk response
                created = 0
                errors = []

                for idx, item in enumerate(result.get("items", [])):
                    if "create" in item:
                        create_result = item["create"]
                        if create_result.get("status") in [200, 201]:
                            created += 1
                        else:
                            # Track error details
                            errors.append(
                                {
                                    "opencti_doc_id": (
                                        doc_ids[idx]
                                        if idx < len(doc_ids)
                                        else "unknown"
                                    ),
                                    "error": create_result.get(
                                        "error", "Unknown error"
                                    ),
                                    "status": create_result.get("status"),
                                }
                            )

                # Log results
                self.helper.connector_logger.info(
                    f"Bulk operation completed: created {created}/{len(observables_data)} indicators",
                    {"errors_count": len(errors), "took_ms": result.get("took", 0)},
                )

                if errors:
                    # Log first few errors for debugging
                    self.helper.connector_logger.warning(
                        "Some indicators failed to create",
                        {"sample_errors": errors[:5]},  # Only log first 5 errors
                    )

                return {
                    "created": created,
                    "total": len(observables_data),
                    "errors": errors,
                    "took": result.get("took", 0),
                }
            else:
                raise ElasticApiHandlerError(
                    f"Failed to bulk create indicators: {response.status_code}",
                    {"response": response.text[:500]},  # Limit response size in logs
                )

        except requests.exceptions.RequestException as e:
            raise ElasticApiHandlerError(
                "Request failed during bulk create operation", {"error": str(e)}
            )

    def update_indicator(self, observable_data: dict) -> Optional[dict]:
        """Update an existing threat indicator in Elastic Security.

        Data streams cannot update a document: a new one replaces it.
        """
        return self._replace_document(observable_data, "update")

    def delete_indicator(self, observable_data: dict) -> bool:
        """Delete a threat indicator from Elastic Security"""
        try:
            doc_id = self._generate_doc_id(observable_data)

            deleted_count = self._delete_docs_by_opencti_id(doc_id)
            self.helper.connector_logger.debug(
                "Successfully deleted indicator(s) from Elastic",
                {"opencti_doc_id": doc_id, "deleted_count": deleted_count},
            )
            return True

        except requests.exceptions.RequestException as e:
            raise ElasticApiHandlerError(
                "Request failed while deleting indicator", {"error": str(e)}
            )

    def test_connection(self) -> bool:
        """Test connection to Elastic Security"""
        try:
            # Check if this is a Kibana URL (contains .kb. or /app)
            is_kibana_url = ".kb." in self.elastic_url or "/app" in self.elastic_url

            if is_kibana_url:
                # For Kibana Cloud deployments, try a simple authenticated request
                # Remove /app from URL if present for API calls
                base_url = self.elastic_url.replace("/app", "")
                url = f"{base_url}/api/status"
            else:
                # For Elasticsearch, use cluster health
                url = f"{self.elastic_url}/_cluster/health"

            response = requests.get(
                url,
                headers=self.headers,
                verify=self._get_verify_config(),
                cert=self.cert,
                timeout=10,
            )

            # Accept various success codes
            if response.status_code in [200, 201, 401, 403]:
                if response.status_code in [401, 403]:
                    self.helper.connector_logger.warning(
                        f"Authentication/Authorization issue with Elastic (status {response.status_code}). Check API key permissions."
                    )
                    return False

                # Try to parse JSON response
                try:
                    if is_kibana_url:
                        status = response.json()
                        self.helper.connector_logger.info(
                            "Successfully connected to Kibana",
                            {
                                "version": status.get("version", {}).get(
                                    "number", "Unknown"
                                )
                            },
                        )
                    else:
                        health = response.json()
                        self.helper.connector_logger.info(
                            "Successfully connected to Elasticsearch",
                            {
                                "cluster_name": health.get("cluster_name"),
                                "status": health.get("status"),
                            },
                        )
                except (ValueError, requests.exceptions.JSONDecodeError) as e:
                    # If JSON parsing fails but we got a 200, consider it a success
                    self.helper.connector_logger.info(
                        f"Connected to Elastic (non-JSON response, likely Kibana web interface): {str(e)}"
                    )
                return True
            else:
                self.helper.connector_logger.error(
                    f"Failed to connect to Elastic: {response.status_code}",
                    {"response": response.text[:500]},  # Limit response text length
                )
                return False

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "Connection test failed", {"error": str(e)}
            )
            return False

    def setup_index_template(self) -> bool:
        """
        Create or update the index template for threat intelligence data

        :return: True if successful, False otherwise
        """
        try:
            # Define the index template with proper ECS mappings
            index_template = {
                "index_patterns": ["logs-ti_custom_opencti.*"],
                "data_stream": {},  # Enable data stream
                "priority": 500,  # Higher priority to override defaults
                "template": {
                    "settings": {
                        "index": {
                            "number_of_shards": 1,
                            "number_of_replicas": 1,
                            "refresh_interval": "5s",
                        }
                    },
                    "mappings": {
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "data_stream": {
                                "properties": {
                                    "dataset": {"type": "keyword"},
                                    "namespace": {"type": "keyword"},
                                    "type": {"type": "keyword"},
                                }
                            },
                            "event": {
                                "properties": {
                                    "kind": {"type": "keyword"},
                                    "category": {"type": "keyword"},
                                    "type": {"type": "keyword"},
                                    "module": {"type": "keyword"},
                                    "dataset": {"type": "keyword"},
                                    "created": {"type": "date"},
                                    "ingested": {"type": "date"},
                                }
                            },
                            "threat": {
                                "properties": {
                                    "indicator": {
                                        "properties": {
                                            # Core fields
                                            "type": {
                                                "type": "keyword"
                                            },  # Critical for sorting
                                            "name": {"type": "keyword"},
                                            "description": {"type": "text"},
                                            # Temporal fields
                                            "first_seen": {"type": "date"},
                                            "last_seen": {"type": "date"},
                                            "modified_at": {"type": "date"},
                                            "valid_from": {"type": "date"},
                                            "valid_until": {"type": "date"},
                                            # Confidence and scoring
                                            "confidence": {
                                                "type": "long"
                                            },  # Numeric confidence
                                            "sightings": {"type": "long"},
                                            # References
                                            "reference": {"type": "keyword"},
                                            "provider": {"type": "keyword"},
                                            # Marking
                                            "marking": {
                                                "properties": {
                                                    "tlp": {"type": "keyword"}
                                                }
                                            },
                                            # IP addresses
                                            "ip": {"type": "ip"},  # Array of IPs
                                            # Domain/URL fields
                                            "url": {
                                                "properties": {
                                                    "domain": {"type": "keyword"},
                                                    "original": {
                                                        "type": "keyword",
                                                        "fields": {
                                                            "text": {"type": "text"}
                                                        },
                                                    },
                                                    "full": {
                                                        "type": "keyword",
                                                        "fields": {
                                                            "text": {"type": "text"}
                                                        },
                                                    },
                                                    "scheme": {"type": "keyword"},
                                                    "path": {"type": "wildcard"},
                                                    "query": {"type": "keyword"},
                                                    "fragment": {"type": "keyword"},
                                                    "port": {"type": "long"},
                                                }
                                            },
                                            # Email
                                            "email": {
                                                "properties": {
                                                    "address": {"type": "keyword"}
                                                }
                                            },
                                            # File hashes
                                            "file": {
                                                "properties": {
                                                    "hash": {
                                                        "properties": {
                                                            "md5": {"type": "keyword"},
                                                            "sha1": {"type": "keyword"},
                                                            "sha256": {
                                                                "type": "keyword"
                                                            },
                                                            "sha512": {
                                                                "type": "keyword"
                                                            },
                                                            "ssdeep": {
                                                                "type": "keyword"
                                                            },
                                                        }
                                                    }
                                                }
                                            },
                                            # AS information
                                            "as": {
                                                "properties": {
                                                    "number": {"type": "long"},
                                                    "organization": {
                                                        "properties": {
                                                            "name": {
                                                                "type": "keyword",
                                                                "fields": {
                                                                    "text": {
                                                                        "type": "text"
                                                                    }
                                                                },
                                                            }
                                                        }
                                                    },
                                                }
                                            },
                                            # Network
                                            "port": {"type": "long"},
                                            "mac": {"type": "keyword"},
                                            # Registry
                                            "registry": {
                                                "properties": {
                                                    "key": {"type": "keyword"},
                                                    "path": {"type": "keyword"},
                                                    "value": {"type": "keyword"},
                                                    "data": {
                                                        "properties": {
                                                            "strings": {
                                                                "type": "wildcard"
                                                            },
                                                            "bytes": {
                                                                "type": "keyword"
                                                            },
                                                        }
                                                    },
                                                }
                                            },
                                            # X509 certificate
                                            "x509": {
                                                "properties": {
                                                    "serial_number": {
                                                        "type": "keyword"
                                                    },
                                                    "issuer": {
                                                        "properties": {
                                                            "distinguished_name": {
                                                                "type": "keyword"
                                                            }
                                                        }
                                                    },
                                                    "subject": {
                                                        "properties": {
                                                            "distinguished_name": {
                                                                "type": "keyword"
                                                            }
                                                        }
                                                    },
                                                }
                                            },
                                            # Query patterns
                                            "query": {"type": "text"},
                                        }
                                    },
                                    "feed": {
                                        "properties": {
                                            "name": {
                                                "type": "keyword"
                                            },  # Important: keyword for aggregations
                                            "reference": {"type": "keyword"},
                                            "description": {"type": "text"},
                                            "dashboard_id": {"type": "keyword"},
                                        }
                                    },
                                }
                            },
                            "related": {
                                "properties": {
                                    "ip": {"type": "ip"},
                                    "hosts": {"type": "keyword"},
                                    "hash": {"type": "keyword"},
                                    "user": {"type": "keyword"},
                                }
                            },
                            # Store raw STIX for reference
                            "stix": {
                                "type": "object",
                                "enabled": False,  # Don't index the raw STIX, just store it
                            },
                        }
                    },
                },
                "_meta": {
                    "description": "Index template for OpenCTI threat intelligence indicators",
                    "managed_by": "elastic_security_intel_connector",
                },
            }

            # Check if template already exists
            check_url = f"{self.elastic_url}/_index_template/logs-ti_custom_opencti"
            check_response = requests.get(
                check_url,
                headers=self.headers,
                verify=self._get_verify_config(),
                cert=self.cert,
            )

            template_exists = check_response.status_code == 200

            # Create or update the index template
            url = f"{self.elastic_url}/_index_template/logs-ti_custom_opencti"
            response = requests.put(
                url,
                headers=self.headers,
                json=index_template,
                verify=self._get_verify_config(),
                cert=self.cert,
            )

            if response.status_code in [200, 201]:
                if template_exists:
                    self.helper.connector_logger.info(
                        "Index template updated successfully",
                        {"template_name": "logs-ti_custom_opencti"},
                    )
                else:
                    self.helper.connector_logger.info(
                        "Index template created successfully",
                        {"template_name": "logs-ti_custom_opencti"},
                    )
                return True
            else:
                self.helper.connector_logger.error(
                    f"Failed to create/update index template: {response.status_code}",
                    {"response": response.text[:500]},
                )
                return False

        except Exception as e:
            self.helper.connector_logger.error(
                "Error setting up index template", {"error": str(e)}
            )
            return False
