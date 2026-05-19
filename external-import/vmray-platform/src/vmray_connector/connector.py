"""
Connect to VMRay and ingest feeds into OpenCTI.
"""

import sys
import time
from datetime import datetime, timezone
from logging import WARNING, getLogger
from re import match as re_match
from re import search
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from pycti import AttackPattern as PyctiAttackPattern
from pycti import OpenCTIConnectorHelper
from pycti import Report as PyctiReport
from pycti import StixCoreRelationship
from stix2 import AttackPattern, Relationship, Report
from stix2.exceptions import InvalidValueError
from vmray.rest_api import VMRayRESTAPI, VMRayRESTAPIError

from .config_loader import ConfigConnector
from .utils import parse_to_vmray_datetime
from .vmray_observable_transform import VMRayObservableTransform
from .vmray_stix_builder import VMRaySTIXBuilder

THREAT_NAMES_REGEX = r"^[a-zA-Z0-9\s]+$"


def build_vtis_lookup(threat_indicators: List[Dict[str, Any]]) -> Dict[int, dict]:
    """
    Build a lookup dictionary for VTI threat indicators by analysis ID.

    Args:
        threat_indicators (List[Dict[str, Any]]): List of threat indicator objects.

    Returns:
        Dict[int, dict]: Lookup dictionary keyed by analysis IDs.
    """
    lookup_dict: Dict[int, dict] = {}

    for threat_indicator in threat_indicators:
        analysis_ids = threat_indicator.get("analysis_ids", [])
        category = threat_indicator.get("category")
        operation = threat_indicator.get("operation")
        score = threat_indicator.get("score", 0)

        for analysis_id in analysis_ids:
            entry = lookup_dict.setdefault(
                analysis_id,
                {"category_operation": {}, "operations": set(), "score": 0},
            )

            if category and operation:
                entry["category_operation"].setdefault(category, set()).add(operation)
                entry["operations"].add(operation)

            if score > entry["score"]:
                entry["score"] = score

    return lookup_dict


def build_mitre_lookup(
    mitre_attack_techniques: List[Dict[str, Any]],
) -> Dict[int, dict]:
    """
    Build a lookup dictionary for MITRE techniques by analysis ID.

    Args:
        mitre_attack_techniques (List[Dict[str, Any]]): List of MITRE attack techniques.

    Returns:
        Dict[int, dict]: Lookup dictionary keyed by analysis IDs.
    """
    lookup_dict: Dict[int, dict] = {}

    for mitre_attack_technique in mitre_attack_techniques:
        analysis_ids = mitre_attack_technique.get("analysis_ids", [])
        technique_id = mitre_attack_technique.get("technique_id")
        technique = mitre_attack_technique.get("technique")
        tactics = mitre_attack_technique.get("tactics", [])
        score = mitre_attack_technique.get("score", 0)

        for aid in analysis_ids:
            entry = lookup_dict.setdefault(
                aid,
                {
                    "techniques": set(),
                    "technique_ids": set(),
                    "tactics": set(),
                    "score": 0,
                },
            )

            if technique:
                entry["techniques"].add(technique)

            if technique_id:
                entry["technique_ids"].add(technique_id)

            if tactics:
                entry["tactics"].update(t.lower() for t in tactics)

            if score > entry["score"]:
                entry["score"] = score

    return lookup_dict


def extract_vti_mitre_labels_by_analysis(
    analysis_ids: List[int],
    vti_lookup: Dict[int, dict],
    mitre_lookup: Dict[int, dict],
) -> Tuple[List[str], List[str]]:
    """
    Extract VTI and MITRE labels for a list of analysis IDs.

    Args:
        analysis_ids (List[int]): List of VMRay analysis IDs.
        vti_lookup (Dict[int, dict]): Lookup dict containing VTI info for each analysis ID.
        mitre_lookup (Dict[int, dict]):
        Lookup dict containing MITRE technique info for each analysis ID.

    Returns:
        tuple[list[str], list[str]]: A tuple containing List of VTI labels and MITRE labels.
    """

    mitre_labels, vti_labels = [], []
    unique_mitre_labels = set()
    unique_vti_labels = set()

    for analysis_id in analysis_ids:
        vti_entry = vti_lookup.get(analysis_id)
        if not vti_entry:
            continue

        for category, operations in vti_entry.get("category_operation", {}).items():
            for operation in operations:
                lbl = f"{category}:{operation}".replace(" ", "_")
                if lbl in unique_vti_labels:
                    continue
                unique_vti_labels.add(lbl)
                vti_labels.append(lbl)

        mitre_entry = mitre_lookup.get(analysis_id)
        if not mitre_entry:
            continue

        for technique_id in mitre_entry.get("technique_ids", []):
            lbl = f"mitre:{technique_id}"
            if lbl in unique_mitre_labels:
                continue
            unique_mitre_labels.add(lbl)
            mitre_labels.append(lbl)

    return vti_labels, mitre_labels


def combine_labels(
    vti: List[str],
    mitre: List[str],
    threat_names: Optional[List[str]] = None,
    classifications: Optional[List[str]] = None,
) -> List[str]:
    """
    Combine VTI, MITRE, threat names, and classifications into a single list of labels.

    Args:
        vti (list[str]): VTI labels.
        mitre (list[str]): MITRE labels.
        threat_names (list[str], optional): Threat name labels.
        classifications (list[str], optional): Classification labels.

    Returns:
        list[str]: Combined list of labels.
    """
    labels = []
    if threat_names:
        labels += threat_names
    if classifications:
        labels += classifications
    labels += vti or []
    labels += mitre or []
    return labels


def build_indicator_description(
    analysis_ids: List[int],
    vti_lookup: Dict[int, dict],
    classifications: Optional[List[str]] = None,
) -> str:
    """
    Build a textual description for an indicator based on classifications and VTI operations.

    Args:
        classifications (List[str]): List of malware classifications associated with the IOC.
        analysis_ids (List[int]): List of VMRay analysis IDs linked to this IOC.
        vti_lookup (Dict[int, dict]): Lookup dict containing VTI operation info per analysis.

    Returns:
        str: A human-readable description summarizing classifications and VTI operations.
    """
    description = "This indicator originates from VMRay Platform."
    if classifications:
        description += (
            f" It was observed with a classification of {', '.join(classifications)}."
        )
    description += "Following detections and observations were recorded:\n"

    operations_list: List[str] = []

    if vti_lookup:
        for aid in analysis_ids:
            vti_entry = vti_lookup.get(aid)
            if vti_entry:
                operations_list.extend(vti_entry.get("operations", []))

    if operations_list:
        bullet_points = "\n".join(
            f"* {op.lower()}" for op in dict.fromkeys(operations_list)
        )
        return description + bullet_points

    return description + "* No VTI operations observed"


def build_killchain_and_confidence(
    analysis_ids: List[int],
    mitre_lookup: Dict[int, Dict],
    vti_lookup: Dict[int, Dict],
) -> Tuple[List[Dict[str, str]], int]:
    """
    Build kill chain phases based on MITRE tactics and calculate confidence score from VTI.
    """
    kill_chain_phases: List[Dict[str, str]] = []
    max_confidence_score: int = 0

    if not analysis_ids:
        return [], 0

    for aid in analysis_ids:
        mitre_entry = mitre_lookup.get(aid) if mitre_lookup else None
        if mitre_entry:
            for tactic in mitre_entry.get("tactics", []):
                kill_chain_phases.append(
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": tactic.lower().replace(" ", "-"),
                    }
                )

        vti_entry = vti_lookup.get(aid) if vti_lookup else None
        if vti_entry:
            max_confidence_score = max(max_confidence_score, vti_entry.get("score", 0))

    return kill_chain_phases, max_confidence_score * 20


class VMRayConnector:
    """
    Class to manage VMRay interactions.
    """

    def __init__(self) -> None:
        """Initialize connector and load configuration."""

        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        getLogger("api").setLevel(WARNING)

        # vmray configurations
        self.vmray_base_url = self.config.vmray_base_url
        self.vmray_api_key = self.config.vmray_api_key
        self.vmray_initial_fetch_date = self.config.initial_fetch_date
        self.duration_period = self.config.duration_period
        self.sample_verdict = [
            v.strip() for v in self.config.sample_verdict.split(",") if v.strip()
        ]
        self.iocs_verdict = [
            v.strip() for v in self.config.iocs_verdict.split(",") if v.strip()
        ]
        default_tlp = self.config.default_tlp.strip().upper()
        tlp_filter = {
            "mode": "and",
            "filters": [
                {"key": "definition", "operator": "eq", "values": [default_tlp]}
            ],
            "filterGroups": [],
        }
        marking_definition = self.helper.api.marking_definition.read(filters=tlp_filter)
        if not marking_definition:
            raise ValueError(f"TLP marking not found for: {default_tlp}")
        self.default_markings = [marking_definition["standard_id"]]
        self.threat_names_color = self.config.threat_names_color
        self.classifications_color = self.config.classifications_color
        self.vti_color = self.config.vti_color
        self.mitre_color = self.config.mitre_color

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="VMRay",
            description="Threat intelligence from VMRay Platform",
            x_opencti_reliability="A - Completely reliable",
        )["standard_id"]

        self.vmray_analyzer_client = VMRayRESTAPI(
            server=self.vmray_base_url,
            api_key=self.vmray_api_key,
            connector_name=self.helper.connect_name,
        )

        self.stix_builder = VMRaySTIXBuilder(
            identity=self.identity,
            default_markings=self.default_markings,
            helper=self.helper,
            threat_names_color=self.threat_names_color,
            classifications_color=self.classifications_color,
            vti_color=self.vti_color,
            mitre_color=self.mitre_color,
        )

    def healthcheck_vmray(self) -> None:
        """
        Validate VMRay API connectivity and credentials.
        Fails fast with clear errors.
        """
        try:
            self.vmray_analyzer_client.call("GET", "/rest/system_info")

        except VMRayRESTAPIError as e:
            status = getattr(e, "status_code", None)

            if status in (401, 403):
                self.helper.connector_logger.error(
                    "[HEALTHCHECK] Invalid VMRay API credentials or insufficient permissions"
                )
                raise

            if status == 400:
                self.helper.connector_logger.error(
                    "[HEALTHCHECK][FAILED] Bad request. "
                    "The server could not understand the request due to invalid syntax."
                )
                raise

            self.helper.connector_logger.error(
                f"[HEALTHCHECK][FAILED] VMRay API error (HTTP {status})"
            )
            raise

        except Exception as e:
            self.helper.connector_logger.error(
                f"[HEALTHCHECK][FAILED] VMRay API unreachable: {str(e)}"
            )
            raise

        self.helper.connector_logger.info(
            "[HEALTHCHECK][OK] VMRay API reachable and credentials valid"
        )

    def retry_api(self, api_callable, *, api_name: str):
        """
        Retry wrapper for VMRay API calls.
        Returns None when sample is skipped.
        """
        last_exception = None
        retryable_statuses = {408, 429, 500, 502, 503}
        non_retryable_statuses = {400, 401, 404}

        for _ in range(2):
            try:
                return api_callable()

            except VMRayRESTAPIError as e:
                status = getattr(e, "status_code", None)

                if status == 403:
                    self.helper.connector_logger.warning(
                        "[VMRay][SKIP] "
                        f"Skipping sample due to Forbidden (403) "
                        f"during {api_name}"
                    )
                    return None

                if status in non_retryable_statuses:
                    self.helper.connector_logger.error(
                        f"[VMRay][ERROR] {api_name} failed with HTTP {status}"
                    )
                    raise

                if status in retryable_statuses:
                    last_exception = e

            except Exception as e:
                last_exception = e

            time.sleep(1)

        self.helper.connector_logger.error(
            f"[VMRay][ERROR] {api_name} failed after retries: {str(last_exception)}"
        )
        raise last_exception

    def get_submissions_by_timestamp(self) -> List[Dict]:
        """
        Fetch all submissions from VMRay within the configured time window.

        Returns:
            List[Dict]: List of submissions.
        """
        params = {"submission_finish_time": f"{self.from_date}~{self.to_date}"}

        all_submissions = self.retry_api(
            lambda: self.vmray_analyzer_client.call(
                "GET", "/rest/submission", params=params
            ),
            api_name="GET /rest/submission",
        )

        if not all_submissions:
            return []

        filtered_submissions = [
            submission
            for submission in all_submissions
            if submission.get("submission_verdict") not in ("clean", None)
        ]

        submissions = sorted(
            filtered_submissions,
            key=lambda s: (
                s.get("submission_finish_time"),
                s.get("submission_sample_id"),
            ),
        )
        return submissions

    def get_sample(self, sample_id: int) -> Dict:
        """
        Fetch a sample by its ID.

        Args:
            sample_id (int): The unique identifier of the sample.

        Returns:
            Optional[Dict]: Sample if found, otherwise None.
        """
        return (
            self.retry_api(
                lambda: self.vmray_analyzer_client.call(
                    "GET", f"/rest/sample/{sample_id}"
                ),
                api_name=f"GET /rest/sample/{sample_id}",
            )
            or {}
        )

    def get_sample_iocs(self, sample_id: int) -> Dict:
        """
        Fetch all IOCs for a given sample ID.

        Args:
            sample_id (int): The sample ID to fetch IOCs for.

        Returns:
            Optional[Dict]: Dictionary of IOCs grouped by type or None.
        """
        return (
            self.retry_api(
                lambda: self.vmray_analyzer_client.call(
                    "GET", f"/rest/sample/{sample_id}/iocs"
                ),
                api_name=f"GET /rest/sample/{sample_id}/iocs",
            )
            or {}
        )

    def get_sample_iocs_by_verdict(self, sample_id: int) -> List[Dict]:
        """
        Fetch IOCs for a sample and filter them by configured IOC verdicts.

        Args:
            sample_id (int): The sample ID.

        Returns:
            Dict[str, List[Dict]]: Filtered IOCs grouped by IOC type.
        """
        ioc_response = self.get_sample_iocs(sample_id)
        if not ioc_response:
            self.helper.connector_logger.debug(
                f"[VMRay] IOC API returned EMPTY for {sample_id}"
            )
            return {}

        raw_iocs = ioc_response.get("iocs", {})

        if not raw_iocs:
            return {}

        filtered_iocs = {}
        allowed_verdicts = {v.lower() for v in self.iocs_verdict}
        for ioc_type, ioc_list in raw_iocs.items():
            ioc_list[:] = [
                ioc
                for ioc in ioc_list
                if ioc.get("verdict", "").lower() in allowed_verdicts
            ]
            if ioc_list:
                filtered_iocs[ioc_type] = ioc_list

        return filtered_iocs

    def fetch_sample_vtis(self, sample_id: int) -> List[Dict]:
        """
        Fetch VMRay Threat Indicators (VTIs) for a sample.

        Args:
            sample_id (int): The sample ID.

        Returns:
            List[Dict]: List of threat indicators.
        """
        data = self.retry_api(
            lambda: self.vmray_analyzer_client.call(
                "GET", f"/rest/sample/{sample_id}/vtis"
            ),
            api_name=f"GET /rest/sample/{sample_id}/vtis",
        )
        return (data or {}).get("threat_indicators", [])

    def fetch_sample_mitre_attacks(self, sample_id: int) -> List[Dict]:
        """
        Fetch MITRE ATT&CK techniques for a sample.

        Args:
            sample_id (int): The sample ID.

        Returns:
            List[Dict]: List of MITRE techniques.
        """
        data = self.retry_api(
            lambda: self.vmray_analyzer_client.call(
                "GET", f"/rest/sample/{sample_id}/mitre_attack"
            ),
            api_name=f"GET /rest/sample/{sample_id}/mitre_attack",
        )
        return (data or {}).get("mitre_attack_techniques", [])

    def build_colored_labels(
        self,
        *,
        threat_names: Optional[List[str]] = None,
        classifications: Optional[List[str]] = None,
        mitre_labels: Optional[List[str]] = None,
        vti_labels: Optional[List[str]] = None,
    ) -> Dict[str, List[str]]:
        """
        Build colored labels for threat names, classifications, MITRE, and VTI.

        Args:
            threat_names (List[str] | None): List of threat names.
            classifications (List[str] | None): List of classifications.
            mitre_labels (List[str] | None): List of MITRE labels.
            vti_labels (List[str] | None): List of VTI labels.

        Returns:
            Dict[str, List[str]]: Dictionary containing colored labels.
        """
        threat_names = threat_names or []
        classifications = classifications or []
        mitre_labels = mitre_labels or []
        vti_labels = vti_labels or []
        colored_labels: Dict[str, List[str]] = {
            "threat_names": [],
            "classifications": [],
            "vti": [],
            "mitre": [],
        }

        colored_labels["threat_names"] = [
            self.helper.api.label.create(
                value=threat_name, color=self.threat_names_color
            ).get("value", threat_name)
            for threat_name in threat_names
        ]
        colored_labels["classifications"] = [
            self.helper.api.label.create(
                value=classification, color=self.classifications_color
            ).get("value", classification)
            for classification in classifications
        ]

        colored_labels["vti"] = [
            self.helper.api.label.create(value=vti_label, color=self.vti_color).get(
                "value", vti_label
            )
            for vti_label in vti_labels
        ]

        colored_labels["mitre"] = [
            self.helper.api.label.create(value=mitre_label, color=self.mitre_color).get(
                "value", mitre_label
            )
            for mitre_label in mitre_labels
        ]

        return colored_labels

    def handle_file_iocs(
        self,
        file_iocs: List[Dict[str, Any]],
        vti_lookup: Dict[int, dict],
        mitre_lookup: Dict[int, dict],
    ) -> List[Any]:
        """
        Process file IOCs and create corresponding STIX objects.

        Args:
            file_iocs (List[Dict[str, Any]]): List of file IOC entries retrieved from VMRay.
            vti_lookup (Dict[int, dict]): Lookup table for VTI data mapped by analysis ID.
            mitre_lookup (Dict[int, dict]): Lookup table for MITRE ATT&CK technique mappings.

        Returns:
            list[Any]: A list containing File Observables,
                       Indicators, Relationships, Malware SDOs and their relationships
        """
        observables: List[Any] = []
        for file_ioc in file_iocs:
            try:
                analysis_ids = file_ioc.get("analysis_ids", [])
                all_threat_names = file_ioc.get("threat_names", [])
                threat_names = [
                    t
                    for t in all_threat_names
                    if isinstance(t, str) and re_match(THREAT_NAMES_REGEX, t)
                ]
                classifications = file_ioc.get("classifications", [])
                vti_labels, mitre_labels = extract_vti_mitre_labels_by_analysis(
                    analysis_ids, vti_lookup, mitre_lookup
                )
                colored = self.build_colored_labels(
                    threat_names=threat_names,
                    classifications=classifications,
                    mitre_labels=mitre_labels,
                    vti_labels=vti_labels,
                )
                all_labels = combine_labels(
                    vti=colored["vti"],
                    mitre=colored["mitre"],
                    threat_names=colored.get("threat_names"),
                    classifications=colored.get("classifications"),
                )
                kill_chain_phases, confidence = build_killchain_and_confidence(
                    analysis_ids, mitre_lookup, vti_lookup
                )

                vmray_hashes = {}
                if file_ioc.get("hashes"):
                    hash_obj = file_ioc["hashes"][0]
                    for vmray_field, stix_key in [
                        ("md5_hash", "MD5"),
                        ("sha1_hash", "SHA1"),
                        ("sha256_hash", "SHA256"),
                    ]:
                        if hash_obj.get(vmray_field):
                            vmray_hashes[stix_key] = hash_obj[vmray_field]
                file_obs = VMRayObservableTransform(
                    observable_type="file",
                    observable_value=file_ioc.get("filename", "unknown"),
                    labels=colored["threat_names"] + colored["classifications"],
                    created_by_ref=self.identity,
                    score=confidence,
                    description="Primary File IOC from VMRay",
                    observable={
                        "hashes": vmray_hashes,
                        "filename": file_ioc.get("filename", "unknown"),
                        "size": file_ioc.get("file_size"),
                        "mime_type": file_ioc.get("mime_type"),
                    },
                    markings=self.default_markings,
                )
                observable_obj = file_obs.stix_observable
                if not observable_obj:
                    continue
                observables.append(observable_obj)
                description = build_indicator_description(
                    analysis_ids, vti_lookup, classifications
                )
                kill_chain_phases, confidence = build_killchain_and_confidence(
                    analysis_ids, mitre_lookup, vti_lookup
                )
                indicator, rel = self.stix_builder.create_indicator_from_observable(
                    observable=observable_obj,
                    labels=all_labels,
                    created_by_ref=self.identity,
                    kill_chain_phases=kill_chain_phases,
                    confidence=confidence,
                    description=description,
                    score=confidence,
                )
                observables.append(indicator)
                observables.append(rel)
                observables += (
                    self.stix_builder.create_malware_objects_for_threat_names(
                        threat_names,
                        classifications,
                        indicator,
                        file_obs,
                        labels=colored["classifications"],
                    )
                )
            except InvalidValueError as e:
                self.helper.connector_logger.error(f"[IOC]Invalid STIX value: {str(e)}")
                continue
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[IOC]Error while creating IOC: {str(e)}"
                )
                continue
        return observables

    def handle_processes_iocs(
        self,
        process_iocs: List[Dict[str, Any]],
        vti_lookup: Dict[int, dict],
        mitre_lookup: Dict[int, dict],
    ) -> List[Any]:
        """
        Handle process IOCs and build all associated STIX objects.
        """
        observables: List[Any] = []

        for process_ioc in process_iocs:
            try:
                cmd_line = process_ioc.get("cmd_line")
                all_threat_names = process_ioc.get("threat_names", [])
                analysis_ids = process_ioc.get("analysis_ids", [])
                threat_names = [
                    t
                    for t in all_threat_names
                    if isinstance(t, str) and re_match(THREAT_NAMES_REGEX, t)
                ]
                classifications = process_ioc.get("classifications", [])
                vti_labels, mitre_labels = extract_vti_mitre_labels_by_analysis(
                    analysis_ids, vti_lookup, mitre_lookup
                )
                colored = self.build_colored_labels(
                    threat_names=threat_names,
                    classifications=classifications,
                    mitre_labels=mitre_labels,
                    vti_labels=vti_labels,
                )
                all_labels = combine_labels(
                    vti=colored["vti"],
                    mitre=colored["mitre"],
                    threat_names=colored.get("threat_names"),
                    classifications=colored.get("classifications"),
                )
                kill_chain_phases, confidence = build_killchain_and_confidence(
                    analysis_ids, mitre_lookup, vti_lookup
                )

                # Create process observable
                process_obs = VMRayObservableTransform(
                    observable_type="process",
                    observable_value=cmd_line,
                    labels=colored["threat_names"] + colored["classifications"],
                    description="Primary Process IOC from VMRay",
                    created_by_ref=self.identity,
                    score=confidence,
                    markings=self.default_markings,
                    observable=process_ioc,
                )

                observable_obj = process_obs.stix_observable
                if not observable_obj:
                    continue
                observables.append(observable_obj)

                description = build_indicator_description(
                    analysis_ids, vti_lookup, classifications
                )

                indicator, rel = self.stix_builder.create_indicator_from_observable(
                    observable=observable_obj,
                    labels=all_labels,
                    created_by_ref=self.identity,
                    kill_chain_phases=kill_chain_phases,
                    confidence=confidence,
                    description=description,
                    score=confidence,
                )
                observables.append(indicator)
                observables.append(rel)

                observables += (
                    self.stix_builder.create_malware_objects_for_threat_names(
                        threat_names,
                        classifications,
                        indicator,
                        process_obs,
                        labels=colored["classifications"],
                    )
                )

            except InvalidValueError as e:
                self.helper.connector_logger.error(f"[IOC]Invalid STIX value: {str(e)}")
                continue
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[IOC]Error while creating IOC: {str(e)}"
                )
                continue
        return observables

    def handle_domain_iocs(
        self,
        domain_iocs: List[Dict[str, Any]],
        vti_lookup: Dict[int, dict],
        mitre_lookup: Dict[int, dict],
    ) -> List[Any]:
        """
        Process Domain IOCs and build all associated STIX objects.
        """
        observables: List[Any] = []

        for domain_ioc in domain_iocs:
            try:
                domain = domain_ioc.get("domain")
                analysis_ids = domain_ioc.get("analysis_ids", [])

                labels = []
                vti_labels, mitre_labels = extract_vti_mitre_labels_by_analysis(
                    analysis_ids, vti_lookup, mitre_lookup
                )
                colored = self.build_colored_labels(
                    mitre_labels=mitre_labels,
                    vti_labels=vti_labels,
                )
                all_labels = combine_labels(vti=colored["vti"], mitre=colored["mitre"])
                kill_chain_phases, confidence = build_killchain_and_confidence(
                    analysis_ids, mitre_lookup, vti_lookup
                )
                for protocol in domain_ioc.get("protocols", []):
                    labels.append(f"protocol: {protocol}")

                domain_obs = VMRayObservableTransform(
                    observable_type="domain",
                    observable_value=domain_ioc["domain"],
                    description="Primary Domain IOC from VMRay",
                    labels=labels,
                    created_by_ref=self.identity,
                    score=confidence,
                    markings=self.default_markings,
                )
                if domain:
                    labels.append(domain)
                observable_obj = domain_obs.stix_observable
                if not observable_obj:
                    continue
                observables.append(observable_obj)

                description = build_indicator_description(
                    analysis_ids=analysis_ids, vti_lookup=vti_lookup
                )

                indicator, rel = self.stix_builder.create_indicator_from_observable(
                    observable=observable_obj,
                    labels=all_labels,
                    created_by_ref=self.identity,
                    kill_chain_phases=kill_chain_phases,
                    confidence=confidence,
                    description=description,
                    score=confidence,
                )
                observables.append(indicator)
                observables.append(rel)

                observables += (
                    self.stix_builder.create_related_obs_for_domain_url_originals(
                        indicator,
                        domain_obs,
                        domain_ioc.get("original_domains", []),
                        "domain",
                        labels,
                        score=confidence,
                    )
                )

                # IP addresses
                for ip in domain_ioc.get("ip_addresses", []):
                    ip_obs = VMRayObservableTransform(
                        observable_type="ip",
                        observable_value=ip,
                        description="IP IOC from VMRay",
                        labels=labels,
                        created_by_ref=self.identity,
                        score=confidence,
                        markings=self.default_markings,
                    )
                    ip_obj = ip_obs.stix_observable
                    if ip_obj:
                        observables.append(ip_obj)
                        rel_ip = ip_obs.create_relationship(
                            src_id=indicator.id,
                            tgt_id=ip_obj.id,
                            markings=self.default_markings,
                            rel_type="based-on",
                        )
                        observables.append(rel_ip)

                observables += self.stix_builder.create_location_objects(
                    indicator,
                    domain_obs,
                    domain_ioc.get("countries", []),
                    domain_ioc.get("country_codes", []),
                    labels,
                )

            except InvalidValueError as e:
                self.helper.connector_logger.error(f"[IOC]Invalid STIX value: {str(e)}")
                continue
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[IOC]Error while creating IOC: {str(e)}"
                )
                continue
        return observables

    def handle_url_iocs(
        self,
        url_iocs: List[Dict[str, Any]],
        vti_lookup: Dict[int, dict],
        mitre_lookup: Dict[int, dict],
    ) -> List[Any]:
        """
        Process URL IOCs and build all associated STIX objects.
        """
        observables: List[Any] = []

        for url_ioc in url_iocs:
            try:
                url = url_ioc.get("url")

                analysis_ids = url_ioc.get("analysis_ids", [])
                labels = []
                vti_labels, mitre_labels = extract_vti_mitre_labels_by_analysis(
                    analysis_ids, vti_lookup, mitre_lookup
                )
                colored = self.build_colored_labels(
                    mitre_labels=mitre_labels,
                    vti_labels=vti_labels,
                )
                all_labels = combine_labels(vti=colored["vti"], mitre=colored["mitre"])
                kill_chain_phases, confidence = build_killchain_and_confidence(
                    analysis_ids, mitre_lookup, vti_lookup
                )

                url_obs = VMRayObservableTransform(
                    observable_type="url",
                    observable_value=url_ioc["url"],
                    description="Primary URL IOC from VMRay",
                    labels=None,
                    created_by_ref=self.identity,
                    score=confidence,
                    markings=self.default_markings,
                )
                observable_obj = url_obs.stix_observable
                if not observable_obj:
                    continue

                observables.append(observable_obj)
                description = build_indicator_description(
                    analysis_ids=analysis_ids, vti_lookup=vti_lookup
                )

                indicator, rel = self.stix_builder.create_indicator_from_observable(
                    observable=observable_obj,
                    labels=all_labels,
                    created_by_ref=self.identity,
                    kill_chain_phases=kill_chain_phases,
                    confidence=confidence,
                    description=description,
                    score=confidence,
                )
                observables.append(indicator)
                observables.append(rel)
                if url:
                    labels.append(url)
                observables += (
                    self.stix_builder.create_related_obs_for_domain_url_originals(
                        indicator,
                        url_obs,
                        url_ioc.get("original_urls", []),
                        "url",
                        labels,
                        score=confidence,
                    )
                )

                # IP addresses
                for ip in url_ioc.get("ip_addresses", []):
                    ip_obs = VMRayObservableTransform(
                        observable_type="ip",
                        observable_value=ip,
                        description="IP IOC from VMRay",
                        labels=labels,
                        created_by_ref=self.identity,
                        score=confidence,
                        markings=self.default_markings,
                    )
                    ip_obj = ip_obs.stix_observable
                    if ip_obj:
                        observables.append(ip_obj)
                        rel_ip = ip_obs.create_relationship(
                            src_id=indicator.id,
                            tgt_id=ip_obj.id,
                            markings=self.default_markings,
                            rel_type="based-on",
                        )
                        observables.append(rel_ip)

                # Countries
                observables += self.stix_builder.create_location_objects(
                    indicator,
                    url_obs,
                    url_ioc.get("countries", []),
                    url_ioc.get("country_codes", []),
                    labels,
                )

            except InvalidValueError as e:
                self.helper.connector_logger.error(f"[IOC]Invalid STIX value: {str(e)}")
                continue
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[IOC]Error while creating IOC: {str(e)}"
                )
                continue
        return observables

    def handle_mutexes_iocs(
        self,
        mutex_iocs: List[Dict[str, Any]],
        vti_lookup: Dict[int, dict],
        mitre_lookup: Dict[int, dict],
    ) -> List[Any]:
        """
        Process Mutex IOCs and build all associated STIX objects.
        """
        observables: List[Any] = []

        for mutex_ioc in mutex_iocs:
            try:
                analysis_ids = mutex_ioc.get("analysis_ids", [])
                all_threat_names = mutex_ioc.get("threat_names", [])
                threat_names = [
                    t
                    for t in all_threat_names
                    if isinstance(t, str) and re_match(THREAT_NAMES_REGEX, t)
                ]
                classifications = mutex_ioc.get("classifications", [])

                vti_labels, mitre_labels = extract_vti_mitre_labels_by_analysis(
                    analysis_ids, vti_lookup, mitre_lookup
                )
                colored = self.build_colored_labels(
                    threat_names=threat_names,
                    classifications=classifications,
                    mitre_labels=mitre_labels,
                    vti_labels=vti_labels,
                )
                all_labels = combine_labels(
                    vti=colored["vti"],
                    mitre=colored["mitre"],
                    threat_names=colored.get("threat_names"),
                    classifications=colored.get("classifications"),
                )
                kill_chain_phases, confidence = build_killchain_and_confidence(
                    analysis_ids, mitre_lookup, vti_lookup
                )

                mutex_obs = VMRayObservableTransform(
                    observable_type="mutex",
                    observable_value=mutex_ioc["mutex_name"],
                    labels=colored["threat_names"] + colored["classifications"],
                    description="Primary Mutex IOC from VMRay",
                    created_by_ref=self.identity,
                    score=confidence,
                    observable=mutex_ioc,
                    markings=self.default_markings,
                )
                observable_obj = mutex_obs.stix_observable
                if not observable_obj:
                    continue
                observables.append(observable_obj)

                description = build_indicator_description(
                    analysis_ids, vti_lookup, classifications
                )

                indicator, rel = self.stix_builder.create_indicator_from_observable(
                    observable=observable_obj,
                    labels=all_labels,
                    created_by_ref=self.identity,
                    kill_chain_phases=kill_chain_phases,
                    confidence=confidence,
                    description=description,
                    score=confidence,
                )
                observables.append(indicator)
                observables.append(rel)

                # Threat Names
                observables += (
                    self.stix_builder.create_malware_objects_for_threat_names(
                        threat_names,
                        classifications,
                        indicator,
                        mutex_obs,
                        labels=colored["classifications"],
                    )
                )

            except InvalidValueError as e:
                self.helper.connector_logger.error(f"[IOC]Invalid STIX value: {str(e)}")
                continue
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[IOC]Error while creating IOC: {str(e)}"
                )
                continue
        return observables

    def handle_registry_iocs(
        self,
        reg_iocs: List[Dict[str, Any]],
        vti_lookup: Dict[int, dict],
        mitre_lookup: Dict[int, dict],
    ) -> List[Any]:
        """
        Process Registry Key IOCs and build all associated STIX objects.
        """
        observables: List[Any] = []

        for reg_ioc in reg_iocs:
            try:
                analysis_ids = reg_ioc.get("analysis_ids", [])
                all_threat_names = reg_ioc.get("threat_names", [])
                threat_names = [
                    t
                    for t in all_threat_names
                    if isinstance(t, str) and re_match(THREAT_NAMES_REGEX, t)
                ]
                classifications = reg_ioc.get("classifications", [])

                vti_labels, mitre_labels = extract_vti_mitre_labels_by_analysis(
                    analysis_ids, vti_lookup, mitre_lookup
                )
                colored = self.build_colored_labels(
                    threat_names=threat_names,
                    classifications=classifications,
                    mitre_labels=mitre_labels,
                    vti_labels=vti_labels,
                )
                all_labels = combine_labels(
                    vti=colored["vti"],
                    mitre=colored["mitre"],
                    threat_names=colored.get("threat_names"),
                    classifications=colored.get("classifications"),
                )
                kill_chain_phases, confidence = build_killchain_and_confidence(
                    analysis_ids, mitre_lookup, vti_lookup
                )

                reg_obs = VMRayObservableTransform(
                    observable_type="registry",
                    observable_value=reg_ioc["reg_key_name"],
                    description="Primary Registry Key IOC from VMRay",
                    labels=colored["threat_names"] + colored["classifications"],
                    created_by_ref=self.identity,
                    score=confidence,
                    markings=self.default_markings,
                    observable=reg_ioc,
                )
                observable_obj = reg_obs.stix_observable
                if not observable_obj:
                    continue
                observables.append(observable_obj)

                description = build_indicator_description(
                    analysis_ids, vti_lookup, classifications
                )

                indicator, rel = self.stix_builder.create_indicator_from_observable(
                    observable=observable_obj,
                    labels=all_labels,
                    created_by_ref=self.identity,
                    kill_chain_phases=kill_chain_phases,
                    confidence=confidence,
                    description=description,
                    score=confidence,
                )
                observables.append(indicator)
                observables.append(rel)

                # Threat Names
                observables += (
                    self.stix_builder.create_malware_objects_for_threat_names(
                        threat_names,
                        classifications,
                        indicator,
                        reg_obs,
                        labels=colored["classifications"],
                    )
                )
            except InvalidValueError as e:
                self.helper.connector_logger.error(f"[IOC]Invalid STIX value: {str(e)}")
                continue
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[IOC]Error while creating IOC: {str(e)}"
                )
                continue
        return observables

    def handle_email_iocs(
        self,
        email_iocs: List[Dict[str, Any]],
        vti_lookup: Dict[int, dict],
        mitre_lookup: Dict[int, dict],
    ) -> List[Any]:
        """
        Process Email Address IOCs and build all associated STIX objects.
        """
        observables: List[Any] = []

        for email_ioc in email_iocs:
            try:
                analysis_ids = email_ioc.get("analysis_ids", [])
                all_threat_names = email_ioc.get("threat_names", [])
                threat_names = [
                    t
                    for t in all_threat_names
                    if isinstance(t, str) and re_match(THREAT_NAMES_REGEX, t)
                ]
                classifications = email_ioc.get("classifications", [])

                vti_labels, mitre_labels = extract_vti_mitre_labels_by_analysis(
                    analysis_ids, vti_lookup, mitre_lookup
                )
                colored = self.build_colored_labels(
                    threat_names=threat_names,
                    classifications=classifications,
                    mitre_labels=mitre_labels,
                    vti_labels=vti_labels,
                )
                all_labels = combine_labels(
                    vti=colored["vti"],
                    mitre=colored["mitre"],
                    threat_names=colored.get("threat_names"),
                    classifications=colored.get("classifications"),
                )
                subject_label = (
                    f"subject:{email_ioc['subject']}"
                    if email_ioc.get("subject")
                    else None
                )
                email_labels = colored["threat_names"] + colored["classifications"]
                if subject_label:
                    email_labels.append(subject_label)
                email_address = search(r"<(.+?)>", email_ioc["sender"])
                observable_value = (
                    email_address.group(1) if email_address else email_ioc["sender"]
                )
                kill_chain_phases, confidence = build_killchain_and_confidence(
                    analysis_ids, mitre_lookup, vti_lookup
                )

                email_obs = VMRayObservableTransform(
                    observable_type="email_address",
                    observable_value=observable_value,
                    description="Primary Email IOC from VMRay",
                    labels=email_labels,
                    created_by_ref=self.identity,
                    score=confidence,
                    markings=self.default_markings,
                    observable=email_ioc,
                )
                observable_obj = email_obs.stix_observable
                if not observable_obj:
                    continue
                observables.append(observable_obj)

                description = build_indicator_description(
                    analysis_ids, vti_lookup, classifications
                )

                indicator, rel = self.stix_builder.create_indicator_from_observable(
                    observable=observable_obj,
                    labels=all_labels,
                    created_by_ref=self.identity,
                    kill_chain_phases=kill_chain_phases,
                    confidence=confidence,
                    description=description,
                    score=confidence,
                )
                observables.append(indicator)
                observables.append(rel)

                # Threat Names
                observables += (
                    self.stix_builder.create_malware_objects_for_threat_names(
                        threat_names,
                        classifications,
                        indicator,
                        email_obs,
                        labels=colored["classifications"],
                    )
                )

            except InvalidValueError as e:
                self.helper.connector_logger.error(f"[IOC]Invalid STIX value: {str(e)}")
                continue
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[IOC]Error while creating IOC: {str(e)}"
                )
                continue
        return observables

    def handle_ip_iocs(
        self,
        ip_iocs: List[Dict[str, Any]],
        vti_lookup: Dict[int, dict],
        mitre_lookup: Dict[int, dict],
    ) -> List[Any]:
        """
        Process IP IOCs and build all associated STIX objects.
        """
        observables: List[Any] = []

        for ip_ioc in ip_iocs:
            try:
                ip = ip_ioc.get("ip_address")
                analysis_ids = ip_ioc.get("analysis_ids", [])
                labels = []
                vti_labels, mitre_labels = extract_vti_mitre_labels_by_analysis(
                    analysis_ids, vti_lookup, mitre_lookup
                )
                colored = self.build_colored_labels(
                    mitre_labels=mitre_labels,
                    vti_labels=vti_labels,
                )
                all_labels = combine_labels(vti=colored["vti"], mitre=colored["mitre"])
                kill_chain_phases, confidence = build_killchain_and_confidence(
                    analysis_ids, mitre_lookup, vti_lookup
                )

                for protocol in ip_ioc.get("protocols", []):
                    labels.append(f"protocol: {protocol}")

                ip_obs = VMRayObservableTransform(
                    observable_type="ip",
                    observable_value=ip_ioc["ip_address"],
                    description="Primary IP IOC from VMRay",
                    labels=labels,
                    created_by_ref=self.identity,
                    score=confidence,
                    markings=self.default_markings,
                )
                observable_obj = ip_obs.stix_observable
                if not observable_obj:
                    continue
                if ip:
                    labels.append(ip)
                observables.append(observable_obj)

                description = build_indicator_description(
                    analysis_ids=analysis_ids, vti_lookup=vti_lookup
                )
                indicator, rel = self.stix_builder.create_indicator_from_observable(
                    observable=observable_obj,
                    labels=all_labels,
                    created_by_ref=self.identity,
                    kill_chain_phases=kill_chain_phases,
                    confidence=confidence,
                    description=description,
                    score=confidence,
                )
                observables.append(indicator)
                observables.append(rel)

                # Domain
                for domain in ip_ioc.get("domains", []):
                    domain_obs = VMRayObservableTransform(
                        observable_type="domain",
                        observable_value=domain,
                        description="Domain IOC from VMRay",
                        labels=labels,
                        created_by_ref=self.identity,
                        score=confidence,
                        markings=self.default_markings,
                    )
                    domain_obj = domain_obs.stix_observable
                    if domain_obj:
                        observables.append(domain_obj)
                        rel_domain = ip_obs.create_relationship(
                            src_id=indicator.id,
                            tgt_id=domain_obj.id,
                            markings=self.default_markings,
                            rel_type="based-on",
                        )
                        observables.append(rel_domain)

                # Countries
                observables += self.stix_builder.create_location_objects(
                    indicator,
                    ip_obs,
                    ip_ioc.get("countries", []),
                    ip_ioc.get("country_codes", []),
                    labels,
                )
            except InvalidValueError as e:
                self.helper.connector_logger.error(f"[IOC]Invalid STIX value: {str(e)}")
                continue
            except Exception as e:
                self.helper.connector_logger.error(
                    f"[IOC]Error while creating IOC: {str(e)}"
                )
                continue
        return observables

    def create_ioc(self, ioc_name: str) -> Callable[[Any, Any, Any], List[Any]]:
        """
        Return the IOC handler function associated with the given IOC type.

        Args:
            ioc_name (str): The name of the IOC category to handle

        Returns:
                 Callable[[Any, Any, Any], List[Any]]: The corresponding IOC handler function,
                    or a fallback function that returns an empty list if the IOC type is unknown.
        """
        indicator_mapping = {
            "files": self.handle_file_iocs,
            "processes": self.handle_processes_iocs,
            "domains": self.handle_domain_iocs,
            "urls": self.handle_url_iocs,
            "mutexes": self.handle_mutexes_iocs,
            "registry": self.handle_registry_iocs,
            "ips": self.handle_ip_iocs,
            "emails": self.handle_email_iocs,
        }
        return indicator_mapping.get(ioc_name, lambda *args, **kwargs: [])

    def build_attack_patterns_and_refs(
        self, mitre_data: List[Dict[str, Any]]
    ) -> Tuple[List[Any], List[Dict[str, Any]]]:
        """
        Build STIX AttackPattern objects and external references from MITRE data.

        Args:
            mitre_data (list[dict]): MITRE technique entries.

        Returns:
            tuple[list, list]: AttackPattern objects and external reference dicts.
        """
        attack_patterns = []
        external_refs = []

        for mitre in mitre_data:
            tid = mitre.get("technique_id")
            tname = mitre.get("technique")
            tactics = mitre.get("tactics", [])

            if not tid or not tname:
                continue

            ext_ref = {
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid}",
            }
            external_refs.append(ext_ref)

            kill_chain_phases = [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": tactic.lower().replace(" ", "-"),
                }
                for tactic in tactics
            ]

            attack_pattern = AttackPattern(
                id=PyctiAttackPattern.generate_id(tname),
                name=tname,
                description="Attack Pattern identified VMRay",
                created_by_ref=self.identity,
                object_marking_refs=self.default_markings,
                allow_custom=True,
                external_references=[ext_ref],
                kill_chain_phases=kill_chain_phases,
            )
            attack_patterns.append(attack_pattern)

        return attack_patterns, external_refs

    def build_sample_stix_objects(
        self, sample: Dict[str, Any]
    ) -> Tuple[Optional[Report], List[Any]]:
        """
        Build all STIX objects for a VMRay sample.

        Args:
            sample (Dict[str, Any]): Raw VMRay sample object.

        Returns:
            Tuple[Optional[Report], List[Any]]: A STIX Report and related STIX objects.
        """
        sample_id = sample.get("sample_id")
        if not sample_id:
            return None, []

        threat_names = [
            t
            for t in sample.get("sample_threat_names", [])
            if isinstance(t, str) and re_match(THREAT_NAMES_REGEX, t)
        ]
        classifications = list(sample.get("sample_classifications", []))

        iocs_by_type = self.get_sample_iocs_by_verdict(sample_id)
        if not iocs_by_type:
            return None, []

        vti_data = self.fetch_sample_vtis(sample_id)
        vti_lookup = build_vtis_lookup(vti_data)
        mitre_data = self.fetch_sample_mitre_attacks(sample_id)
        mitre_lookup = build_mitre_lookup(mitre_data)
        analysis_ids = [
            aid
            for iocs in iocs_by_type.values()
            for ioc in iocs
            for aid in ioc.get("analysis_ids", [])
        ]

        vti_labels, mitre_labels = extract_vti_mitre_labels_by_analysis(
            analysis_ids, vti_lookup, mitre_lookup
        )
        colored = self.build_colored_labels(
            threat_names=threat_names,
            classifications=classifications,
            mitre_labels=mitre_labels,
            vti_labels=vti_labels,
        )
        all_labels = combine_labels(
            vti=colored["vti"],
            mitre=colored["mitre"],
            threat_names=colored.get("threat_names"),
            classifications=colored.get("classifications"),
        )

        stix_objects: List[Any] = []
        for ioc_type, ioc_list in iocs_by_type.items():
            filtered_ioc_list = [
                ioc
                for ioc in ioc_list
                if "Memory Dump" not in ioc.get("categories", [])
                and ioc.get("ioc", False)
            ]
            if not filtered_ioc_list:
                continue
            handler = self.create_ioc(ioc_type)
            ioc_objects = handler(filtered_ioc_list, vti_lookup, mitre_lookup)
            if ioc_objects:
                stix_objects.extend(ioc_objects)

        if not stix_objects:
            return None, []

        attack_patterns, external_refs = self.build_attack_patterns_and_refs(mitre_data)
        stix_objects.extend(attack_patterns)
        created_date = sample.get("sample_created")
        published_date = (
            datetime.fromisoformat(created_date).replace(tzinfo=timezone.utc)
            if created_date
            else datetime.now(timezone.utc)
        )
        web_url = sample.get("sample_webif_url")
        if web_url:
            external_refs.append(
                {
                    "source_name": "vmray-sample",
                    "url": web_url,
                    "description": "VMRay Sample Web Interface URL",
                }
            )
        self.helper.connector_logger.debug(
            f"Creating Stix objects and report for sample {sample_id}"
        )
        description = (
            f"Report for Sample ID {sample_id}. "
            "Marks one or more indicators and cyber observables that "
            "originate from a common analysis such as a detonation."
        )
        rep_name = f"VMRay Platform STIX 2.1 Analysis Report - report--{uuid4()}"
        report = Report(
            id=PyctiReport.generate_id(rep_name, published_date),
            name=rep_name,
            description=description,
            published=published_date,
            labels=all_labels,
            report_types=["observed-data"],
            object_marking_refs=self.default_markings,
            x_opencti_reliability="A - Completely reliable",
            created_by_ref=self.identity,
            object_refs=[obj.id for obj in stix_objects],
            external_references=external_refs,
            allow_custom=True,
        )

        return report, stix_objects

    def update_parent_child_map_for_sample(
        self,
        parent_child_map: Dict[int, Set[int]],
        child_parent_map: Dict[int, Set[int]],
        sample: Dict[str, Any],
    ) -> None:
        """
        Incrementally update parent-child and child-parent mappings using a single sample.
        """
        parent_id = sample.get("sample_id")
        if parent_id is None:
            return

        child_ids = sample.get("sample_child_sample_ids") or []
        if not child_ids:
            return

        for child_id in child_ids:
            parent_child_map.setdefault(parent_id, set()).add(child_id)
            child_parent_map.setdefault(child_id, set()).add(parent_id)

    def create_parent_child_relationships_for_sample(
        self,
        sample_id: int,
        sample_reports: Dict[int, Report],
        parent_child_map: Dict[int, Set[int]],
        child_parent_map: Dict[int, Set[int]],
        verdict_passed_sample_ids: Set[int],
    ) -> List[Relationship]:
        """
        Create parent-child relationships only if BOTH parent and child
        samples passed the verdict filter.
        """
        relationships: List[Relationship] = []

        if sample_id not in verdict_passed_sample_ids:
            return relationships

        current_report = sample_reports.get(sample_id)
        if not current_report:
            return relationships

        # Parents → current
        for parent_id in child_parent_map.get(sample_id, set()):
            if parent_id not in verdict_passed_sample_ids:
                continue

            parent_report = sample_reports.get(parent_id)
            if not parent_report:
                continue

            relationships.append(
                Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", parent_report.id, current_report.id
                    ),
                    source_ref=parent_report.id,
                    target_ref=current_report.id,
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    object_marking_refs=self.default_markings,
                    allow_custom=True,
                )
            )

        # Current → children
        for child_id in parent_child_map.get(sample_id, set()):
            if child_id not in verdict_passed_sample_ids:
                continue

            child_report = sample_reports.get(child_id)
            if not child_report:
                continue

            relationships.append(
                Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", current_report.id, child_report.id
                    ),
                    source_ref=current_report.id,
                    target_ref=child_report.id,
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    object_marking_refs=self.default_markings,
                    allow_custom=True,
                )
            )

        return relationships

    def process_single_sample(
        self,
        sample: Dict[str, Any],
        *,
        work_id: str,
        sample_reports: Dict[int, Report],
        parent_child_map: Dict[int, Set[int]],
        child_parent_map: Dict[int, Set[int]],
        verdict_passed_sample_ids: Set[int],
    ) -> None:
        """
        Process exactly one VMRay sample, immediately send its report,
        and create relationships if possible.
        """
        sample_id = sample.get("sample_id")
        self.helper.connector_logger.info(f"[SAMPLE] Processing sample_id={sample_id}")

        try:
            report, stix_objects = self.build_sample_stix_objects(sample)

            if not report:
                self.helper.connector_logger.debug(
                    f"[REPORT][SKIP] sample_id={sample_id} reason=no_report_created"
                )
                return

            # Send report immediately
            bundle = self.helper.stix2_create_bundle(stix_objects + [report])
            self.helper.send_stix2_bundle(bundle=bundle, update=True, work_id=work_id)

            # Register report
            sample_reports[sample_id] = report

            # Update relationship maps
            self.update_parent_child_map_for_sample(
                parent_child_map=parent_child_map,
                child_parent_map=child_parent_map,
                sample=sample,
            )

            # Create relationships if resolvable
            relationships = self.create_parent_child_relationships_for_sample(
                sample_id=sample_id,
                sample_reports=sample_reports,
                parent_child_map=parent_child_map,
                child_parent_map=child_parent_map,
                verdict_passed_sample_ids=verdict_passed_sample_ids,
            )

            if relationships:
                rel_bundle = self.helper.stix2_create_bundle(relationships)
                self.helper.send_stix2_bundle(rel_bundle, update=True, work_id=work_id)

        except Exception as e:
            self.helper.connector_logger.error(
                f"[VMRay] Failed processing sample {sample_id}: {str(e)}"
            )
            raise

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence from VMRay.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            self.healthcheck_vmray()
            state = self.helper.get_state() or {}
            last_run = state.get("last_run")
            failed_sample_id = state.get("failed_sample_id")

            self.helper.connector_logger.info(
                f"[STATE] last_run={last_run}, failed_sample_id={failed_sample_id}"
            )

            get_timestamp = parse_to_vmray_datetime(datetime.now(timezone.utc))

            self.from_date = (
                parse_to_vmray_datetime(last_run)
                if last_run
                else parse_to_vmray_datetime(self.vmray_initial_fetch_date)
            )
            self.to_date = get_timestamp
            self.helper.connector_logger.info(
                f"Fetching submissions from {self.from_date} to {self.to_date}"
            )

            submissions = self.get_submissions_by_timestamp()
            self.helper.connector_logger.info(f"Fetched {len(submissions)} submissions")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, self.helper.connect_name
            )

            processed_sample_ids: Set[int] = set()
            verdict_passed_sample_ids: Set[int] = set()
            sample_reports: Dict[int, Report] = {}
            parent_child_map: Dict[int, Set[int]] = {}
            child_parent_map: Dict[int, Set[int]] = {}
            finish_time = None
            run_successful = False
            if submissions:
                try:
                    # Main processing loop
                    for submission in submissions:
                        sample_id = submission.get("submission_sample_id")
                        finish_time = submission.get("submission_finish_time")

                        if not isinstance(sample_id, int):
                            continue
                        if failed_sample_id is not None:
                            if sample_id != failed_sample_id:
                                continue
                            failed_sample_id = None

                        if sample_id in processed_sample_ids:
                            continue
                        processed_sample_ids.add(sample_id)
                        sample = self.get_sample(sample_id)

                        if not sample:
                            continue

                        if sample.get("sample_verdict") not in self.sample_verdict:
                            continue

                        verdict_passed_sample_ids.add(sample_id)

                        self.process_single_sample(
                            sample,
                            work_id=work_id,
                            sample_reports=sample_reports,
                            parent_child_map=parent_child_map,
                            child_parent_map=child_parent_map,
                            verdict_passed_sample_ids=verdict_passed_sample_ids,
                        )
                    run_successful = True
                except Exception as e:
                    self.helper.connector_logger.error(
                        f"Failed to fetch sample_id={sample_id} {str(e)}"
                    )
                    self.helper.set_state(
                        {"last_run": finish_time, "failed_sample_id": sample_id}
                    )
                    raise
            else:
                self.helper.connector_logger.info("No submissions to process")
                self.helper.set_state(
                    {"last_run": get_timestamp, "failed_sample_id": None}
                )
            if run_successful:
                self.helper.set_state(
                    {"last_run": get_timestamp, "failed_sample_id": None}
                )
                message = (
                    f"{self.helper.connect_name} connector successfully run, storing last_run as "
                    + str(get_timestamp)
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.connector_logger.info(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(
                f"[FATAL] Connector run aborted: {str(e)}"
            )

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler.

        This scheduler allows you to run the process at certain intervals. It also checks the
        connector queue size. If `CONNECTOR_QUEUE_THRESHOLD` is set and the queue size exceeds
        the threshold, the main process will not run until the queue is sufficiently reduced,
        allowing it to restart during the next scheduler check (default threshold is 500MB).

        Requires the `duration_period` connector variable in ISO-8601 format. Example:
        `CONNECTOR_DURATION_PERIOD=PT5M` will run the process every 5 minutes.

        Returns:
            None
        """

        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.duration_period,
        )
