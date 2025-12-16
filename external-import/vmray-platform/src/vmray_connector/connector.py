"""
Connect to VMRay and ingest feeds into OpenCTI.
"""

from datetime import datetime, timezone
from logging import WARNING, getLogger
from re import match as re_match
from re import search
from sys import exit
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from pycti import OpenCTIConnectorHelper
from requests.exceptions import (
    ConnectionError,
    ProxyError,
    RequestException,
    SSLError,
    Timeout,
    TooManyRedirects,
)
from stix2 import AttackPattern, Relationship, Report
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
        mitre_lookup (Dict[int, dict]): Lookup dict containing MITRE technique info for each analysis ID.

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


def build_parent_child_map(samples: List[Dict[str, Any]]) -> Dict[int, List[int]]:
    """
    Build a mapping of parent sample IDs to their child sample IDs.

    Args:
        samples (List[Dict[str, Any]]): List of sample dictionaries.

    Returns:
        Dict[int, List[int]]: Mapping from parent sample ID to list of child sample IDs.
    """
    mapping = {}
    for sample in samples:
        parent_id = sample.get("sample_id")
        if parent_id is None:
            continue
        child_ids = sample.get("sample_child_sample_ids") or []
        if child_ids:
            mapping[parent_id] = [c for c in child_ids if c is not None]
    return mapping


class VMRayConnector:
    """
    Class to manage VMRay interactions.
    """

    def __init__(self) -> None:
        """Initialize connector and load configuration."""

        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.logger = self.helper.connector_logger
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
        self.vmray_headers = {
            "Authorization": f"api_key {self.vmray_api_key}",
            "User-Agent": "OpenCTI",
            "Accept": "application/json",
        }

        self.stix_builder = VMRaySTIXBuilder(
            identity=self.identity,
            default_markings=self.default_markings,
            helper=self.helper,
            threat_names_color=self.threat_names_color,
            classifications_color=self.classifications_color,
            vti_color=self.vti_color,
            mitre_color=self.mitre_color,
        )

    def get_submissions_by_timestamp(self) -> List[Dict]:
        """
        Fetch all submissions from VMRay within the configured time window.

        Returns:
            List[Dict]: List of submissions.
        """
        all_submissions: List[Dict] = []
        params = {"submission_finish_time": f"{self.from_date}~{self.to_date}"}

        try:
            submission_data = self.vmray_analyzer_client.call(
                "GET", f"/rest/submission", params=params
            )
            if submission_data:
                all_submissions.extend(submission_data)
        except VMRayRESTAPIError as e:
            self.logger.error(
                f"[VMRay] Submission API error: '{e}' (HTTP {e.status_code})"
            )
        except (Timeout, ConnectionError, SSLError, ProxyError, TooManyRedirects) as e:
            self.logger.error(
                f"[VMRay] Network error while fetching submissions: {type(e).__name__}: {e}"
            )
        except RequestException as e:
            self.logger.error(f"[VMRay] Request error while fetching submissions: {e}")
        except Exception as e:
            self.logger.error(f"[VMRay] Unexpected error fetching submissions: {e}")

        return all_submissions

    def get_sample(self, sample_id: int) -> Optional[Dict]:
        """
        Fetch details of a sample by its ID.

        Args:
            sample_id (int): The unique identifier of the sample.

        Returns:
            Optional[Dict]: Sample details if found, otherwise None.
        """
        try:
            sample_data = self.vmray_analyzer_client.call(
                "GET", f"/rest/sample/{sample_id}"
            )
            return sample_data
        except VMRayRESTAPIError as e:
            self.logger.error(
                f"[VMRay] Error fetching sample {sample_id}: '{e}' (HTTP {e.status_code})"
            )
        except (Timeout, ConnectionError, SSLError, ProxyError, TooManyRedirects) as e:
            self.logger.error(
                f"[VMRay] Network error fetching sample {sample_id}: {type(e).__name__}: {e}"
            )
        except RequestException as e:
            self.logger.error(f"[VMRay] Request error fetching sample {sample_id}: {e}")
        except Exception as e:
            self.logger.error(
                f"[VMRay] Unexpected error fetching sample {sample_id}: {e}"
            )
        return None

    def get_samples_by_verdict(self, sample_ids: Set[int]) -> List[Dict]:
        """
        Fetch samples and filter them based on the configured sample verdicts.

        Args:
            sample_ids (Set[int]): Set of sample IDs to fetch.

        Returns:
            List[Dict]: List of samples that match the configured verdicts.
        """
        self.logger.info(
            f"[VMRay] Fetching samples for verdict filtering: {sample_ids}"
        )

        samples_by_verdict = []
        for sample_id in sample_ids:
            sample = self.get_sample(sample_id)
            if sample is None:
                continue

            verdict = sample.get("sample_verdict") or sample.get("verdict")

            if verdict in self.sample_verdict:
                samples_by_verdict.append(sample)

        self.logger.info(
            f"[VMRay] Total samples passing verdict: {len(samples_by_verdict)}"
        )

        return samples_by_verdict

    def get_sample_iocs(self, sample_id: int) -> Optional[Dict]:
        """
        Fetch all IOCs for a given sample ID.

        Args:
            sample_id (int): The sample ID to fetch IOCs for.

        Returns:
            Optional[Dict]: Dictionary of IOCs grouped by type or None.
        """
        try:
            sample_iocs_data = self.vmray_analyzer_client.call(
                "GET", f"/rest/sample/{sample_id}/iocs"
            )
            return sample_iocs_data
        except VMRayRESTAPIError as e:
            self.logger.error(
                f"[VMRay] Error fetching IOCs for sample {sample_id}: '{e}' (HTTP {e.status_code})"
            )
        except (Timeout, ConnectionError, SSLError, ProxyError, TooManyRedirects) as e:
            self.logger.error(
                f"[VMRay] Network error fetching IOCs for sample {sample_id}: {type(e).__name__}: {e}"
            )
        except RequestException as e:
            self.logger.error(
                f"[VMRay] Request error fetching IOCs for sample {sample_id}: {e}"
            )
        except Exception as e:
            self.logger.error(
                f"[VMRay] Unexpected error fetching IOCs for sample {sample_id}: {e}"
            )
        return None

    def get_sample_iocs_by_verdict(self, sample_id: int) -> Dict[str, List[Dict]]:
        """
        Fetch IOCs for a sample and filter them by configured IOC verdicts.

        Args:
            sample_id (int): The sample ID.

        Returns:
            Dict[str, List[Dict]]: Filtered IOCs grouped by IOC type.
        """
        self.logger.info(f"[VMRay] Fetching IOCs for sample {sample_id}")

        ioc_response = self.get_sample_iocs(sample_id)
        if not ioc_response:
            self.logger.warning(f"[VMRay] IOC API returned EMPTY for {sample_id}")
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

    def fetch_sample_vtis(self, sample_id: int) -> List[Dict[str, Any]]:
        """
        Fetch VMRay Threat Indicators (VTIs) for a sample.

        Args:
            sample_id (int): The sample ID.

        Returns:
            List[Dict[str, Any]]: List of threat indicators.
        """
        try:
            vtis_data = self.vmray_analyzer_client.call(
                "GET", f"/rest/sample/{sample_id}/vtis"
            )
            threat_indicators = vtis_data.get("threat_indicators", [])
            self.logger.info(
                f"[VMRay] Retrieved {len(threat_indicators)} VTIs for sample {sample_id}"
            )
            return threat_indicators or []

        except VMRayRESTAPIError as e:
            self.logger.error(
                f"[VMRay] No VTIs for sample {sample_id}: '{e}' (HTTP {e.status_code})"
            )
        except (Timeout, ConnectionError, SSLError, ProxyError, TooManyRedirects) as e:
            self.logger.error(
                f"[VMRay] Network error fetching VTIs for sample {sample_id}: {type(e).__name__}: {e}"
            )
        except RequestException as e:
            self.logger.error(
                f"[VMRay] Request error fetching VTIs for sample {sample_id}: {e}"
            )
        except Exception as e:
            self.logger.error(
                f"[VMRay] Unexpected error fetching VTIs for sample {sample_id}: {e}"
            )
        return []

    def fetch_sample_mitre_attacks(self, sample_id: int) -> List[Dict[str, Any]]:
        """
        Fetch MITRE ATT&CK techniques for a sample.

        Args:
            sample_id (int): The sample ID.

        Returns:
            List[Dict[str, Any]]: List of MITRE techniques.
        """
        try:
            vtis_data = self.vmray_analyzer_client.call(
                "GET", f"/rest/sample/{sample_id}/mitre_attack"
            )
            mitre_attack_techniques = vtis_data.get("mitre_attack_techniques", [])
            self.logger.info(
                f"[VMRay] Retrieved {len(mitre_attack_techniques)} MITRE ATT&CK techniques for sample {sample_id}"
            )
            return mitre_attack_techniques or []

        except VMRayRESTAPIError as e:
            self.logger.error(
                f"[VMRay] No MITRE ATT&CK techniques for sample {sample_id}: '{e}' (HTTP {e.status_code})"
            )
        except (Timeout, ConnectionError, SSLError, ProxyError, TooManyRedirects) as e:
            self.logger.error(
                f"[VMRay] Network error fetching MITRE ATT&CK for sample {sample_id}: {type(e).__name__}: {e}"
            )
        except RequestException as e:
            self.logger.error(
                f"[VMRay] Request error fetching MITRE ATT&CK for sample {sample_id}: {e}"
            )
        except Exception as e:
            self.logger.error(
                f"[VMRay] Unexpected error fetching MITRE ATT&CK for sample {sample_id}: {e}"
            )
        return []

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
            observables += self.stix_builder.create_malware_objects_for_threat_names(
                threat_names,
                classifications,
                indicator,
                file_obs,
                labels=colored["classifications"],
            )
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
                description=f"Primary Process IOC from VMRay",
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

            observables += self.stix_builder.create_malware_objects_for_threat_names(
                threat_names,
                classifications,
                indicator,
                process_obs,
                labels=colored["classifications"],
            )

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
                description=f"Primary Domain IOC from VMRay",
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
                    description=f"IP IOC from VMRay",
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
                description=f"Primary URL IOC from VMRay",
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
                    description=f"IP IOC from VMRay",
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
                description=f"Primary Mutex IOC from VMRay",
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
            observables += self.stix_builder.create_malware_objects_for_threat_names(
                threat_names,
                classifications,
                indicator,
                mutex_obs,
                labels=colored["classifications"],
            )

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
                description=f"Primary Registry Key IOC from VMRay",
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
            observables += self.stix_builder.create_malware_objects_for_threat_names(
                threat_names,
                classifications,
                indicator,
                reg_obs,
                labels=colored["classifications"],
            )

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
                f"subject:{email_ioc['subject']}" if email_ioc.get("subject") else None
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
                description=f"Primary Email IOC from VMRay",
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
            observables += self.stix_builder.create_malware_objects_for_threat_names(
                threat_names,
                classifications,
                indicator,
                email_obs,
                labels=colored["classifications"],
            )

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
                description=f"Primary IP IOC from VMRay",
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
                    description=f"Domain IOC from VMRay",
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
        self.helper.connector_logger.info(
            f"Creating Stix objects and report for sample {sample_id}"
        )
        description = (
            f"Report for Sample ID {sample_id}. "
            "Marks one or more indicators and cyber observables that "
            "originate from a common analysis such as a detonation."
        )
        report = Report(
            name=f"VMRay Platform STIX 2.1 Analysis Report - report--{uuid4()}",
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

    def create_parent_child_relationships(
        self, sample_reports: Dict[int, Report], parent_child_map: Dict[int, List[int]]
    ) -> List[Relationship]:
        """
        Create relationships between parent and child sample reports.

        Args:
                sample_reports (Dict[int, Report]): Mapping of sample IDs to Report objects.
                parent_child_map (Dict[int, List[int]]): Mapping of parent IDs to list of child IDs.

        Returns:
            List[Relationship]: List of Relationship objects representing parent-child links.
        """
        relationships = []
        for parent_id, child_ids in parent_child_map.items():
            parent_report = sample_reports.get(parent_id)
            if not parent_report:
                continue
            for child_id in child_ids:
                child_report = sample_reports.get(child_id)
                if not child_report:
                    continue
                if child_report:
                    relationships.append(
                        Relationship(
                            source_ref=parent_report.id,
                            target_ref=child_report.id,
                            relationship_type="related-to",
                            created_by_ref=self.identity,
                            object_marking_refs=self.default_markings,
                        )
                    )
        return relationships

    def process_samples(self, samples: List[Dict[str, Any]]) -> List[Any]:
        """
        Process multiple VMRay samples into full STIX objects with reports and relationships.

        Args:
            samples (List[Dict[str, Any]]): List of VMRay samples.

        Returns:
             List[Any]: All generated STIX objects including reports and parent–child relationships.
        """
        all_objects = []
        sample_reports = {}

        for sample in samples:
            report, stix_objects = self.build_sample_stix_objects(sample)
            if not report:
                continue
            sample_id = sample.get("sample_id")
            if sample_id is None:
                continue
            sample_reports[sample_id] = report
            all_objects.extend(stix_objects)
            all_objects.append(report)

        parent_child_map = build_parent_child_map(samples)
        relationships = self.create_parent_child_relationships(
            sample_reports, parent_child_map
        )
        all_objects.extend(relationships)

        return all_objects

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence from VMRay.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )
        try:
            # Load last run timestamp
            current_state = self.helper.get_state()
            last_run = current_state.get("last_run") if current_state else None
            next_checkpoint = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            if last_run:
                self.from_date = parse_to_vmray_datetime(last_run)
                self.helper.connector_logger.info(
                    f"[VMRay] Using last_run as from_date: {self.from_date}"
                )
            else:
                self.from_date = parse_to_vmray_datetime(self.vmray_initial_fetch_date)
                self.helper.connector_logger.info(
                    f"[VMRay] Using initial_fetch_date as from_date: {self.from_date}"
                )

            # Always set the new end time
            self.to_date = parse_to_vmray_datetime(datetime.now(timezone.utc))

            self.helper.connector_logger.info("Connecting to VMRay...")

            # Fetch submissions
            vmray_submissions = self.get_submissions_by_timestamp()
            self.helper.connector_logger.info(
                f"[VMRay] Fetched {len(vmray_submissions)} submissions "
                f"from {self.from_date} to {self.to_date}"
            )

            # Friendly name for OpenCTI
            friendly_name = self.helper.connect_name

            # Initiate work in OpenCTI
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            # Process submissions
            unique_sample_ids = set(
                [x["submission_sample_id"] for x in vmray_submissions]
            )
            vmray_samples_by_verdict = self.get_samples_by_verdict(unique_sample_ids)
            processed_objects = self.process_samples(vmray_samples_by_verdict)

            self.logger.info(
                f"[VMRay] Total processed objects: {len(processed_objects)}"
            )

            if processed_objects:
                self.logger.info("[VMRay] Sending STIX bundle to OpenCTI...")
                all_bundle = self.helper.stix2_create_bundle(processed_objects)
                self.helper.send_stix2_bundle(
                    bundle=all_bundle, update=True, work_id=work_id
                )
            else:
                self.logger.info("[VMRay] FINAL RESULT: No new data to process.")

            self.helper.set_state({"last_run": next_checkpoint})
            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                f"{next_checkpoint}"
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

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
