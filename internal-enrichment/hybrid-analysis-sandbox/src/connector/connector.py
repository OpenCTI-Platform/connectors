import time
from copy import deepcopy
from datetime import datetime
from urllib.parse import urljoin

import stix2
from connector.settings import ConnectorSettings
from hybrid_analysis_client import HybridAnalysisAPIError, HybridAnalysisClient
from pycti import (
    AttackPattern,
    Identity,
    MalwareAnalysis,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class HybridAnalysisReportError(Exception):
    """Custom exception for errors related to Hybrid Analysis processing file."""


class HybridAnalysis:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = HybridAnalysisClient(
            helper,
            token=self.config.hybrid_analysis_sandbox.token.get_secret_value(),
            environment_id=self.config.hybrid_analysis_sandbox.environment_id,
        )

        self.max_tlp = self.config.hybrid_analysis_sandbox.max_tlp

        # Author to add to ingested objects
        self.identity = stix2.Identity(
            id=Identity.generate_id(
                name="Hybrid Analysis", identity_class="organization"
            ),
            name="Hybrid Analysis",
            identity_class="organization",
            description="Hybrid Analysis Sandbox.",
        )
        # TLP marking to apply to ingested objects
        self.tlp = stix2.TLP_WHITE

    def _create_knowledge(
        self, stix_entity: dict, opencti_entity: dict, report: dict
    ) -> list[stix2.v21._STIXBase21]:
        """Create STIX objects based on the Hybrid Analysis report.
        :param stix_entity: The original STIX entity being enriched.
        :param opencti_entity: The OpenCTI representation of the entity being enriched.
        :param report: The Hybrid Analysis report data.
        :return: A list of enriched STIX objects.
        """
        # Do not modify original entity (to avoid side effects in case of error)
        enriched_entity = deepcopy(stix_entity)

        # Replace original entity with enriched entity
        enriched_objects = [
            (
                enriched_entity
                if stix_object["id"] == enriched_entity["id"]
                else stix_object
            )
            for stix_object in self.stix_objects
        ]

        if opencti_entity["entity_type"] in ["StixFile", "Artifact"]:
            # Modifying the hashes will produce new `Standard STIX ID`s on OpenCTI side
            # This is an **expected** behavior handled by OpenCTI during bundle ingestion
            enriched_entity_hashes = enriched_entity.get("hashes", {})
            if report["md5"] is not None:
                enriched_entity_hashes["MD5"] = report["md5"]
            if report["sha1"] is not None:
                enriched_entity_hashes["SHA-1"] = report["sha1"]
            if report["sha256"] is not None:
                enriched_entity_hashes["SHA-256"] = report["sha256"]
            enriched_entity["hashes"] = enriched_entity_hashes

            if report["submit_name"] is not None:
                enriched_entity["x_opencti_additional_names"] = report["submit_name"]

        if opencti_entity["entity_type"] == "StixFile":
            enriched_entity["size"] = report["size"]

        if report["threat_score"] is not None:
            enriched_entity["x_opencti_score"] = report["threat_score"]

        operating_system = None
        if report["environment_id"] is not None:
            operating_system = stix2.Software(name=report["environment_description"])
            enriched_objects.append(operating_system)

        analysis_sco_refs = []

        for tag in report["type_short"]:
            if enriched_entity.get("labels") is None:
                enriched_entity["labels"] = []
            enriched_entity["labels"].append(tag)

        for tactic in report["mitre_attcks"]:
            if (
                tactic["malicious_identifiers_count"] > 0
                or tactic["suspicious_identifiers_count"] > 0
            ):
                attack_pattern = stix2.AttackPattern(
                    id=AttackPattern.generate_id(
                        tactic["technique"], tactic["attck_id"]
                    ),
                    created_by_ref=self.identity.id,
                    name=tactic["technique"],
                    custom_properties={"x_mitre_id": tactic["attck_id"]},
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", enriched_entity["id"], attack_pattern.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity.id,
                    source_ref=enriched_entity["id"],
                    target_ref=attack_pattern.id,
                    object_marking_refs=[self.tlp],
                )
                enriched_objects.append(attack_pattern)
                enriched_objects.append(relationship)

        for domain in report["domains"]:
            if domain != opencti_entity["observable_value"]:
                domain_stix = stix2.DomainName(
                    value=domain,
                    object_marking_refs=[self.tlp],
                    custom_properties={"x_opencti_created_by_ref": self.identity.id},
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", enriched_entity["id"], domain_stix.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity.id,
                    source_ref=enriched_entity["id"],
                    target_ref=domain_stix.id,
                    object_marking_refs=[self.tlp],
                )
                analysis_sco_refs.append(domain_stix.id)
                enriched_objects.append(domain_stix)
                enriched_objects.append(relationship)

        for host in report["hosts"]:
            if self.detect_ip_version(host) == "IPv4-Addr":
                host_stix = stix2.IPv4Address(
                    value=host,
                    object_marking_refs=[self.tlp],
                    custom_properties={"x_opencti_created_by_ref": self.identity.id},
                )
            else:
                host_stix = stix2.IPv6Address(
                    value=host,
                    object_marking_refs=[self.tlp],
                    custom_properties={"x_opencti_created_by_ref": self.identity.id},
                )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", enriched_entity["id"], host_stix.id
                ),
                relationship_type="related-to",
                created_by_ref=self.identity.id,
                source_ref=enriched_entity["id"],
                target_ref=host_stix.id,
                object_marking_refs=[self.tlp],
            )
            analysis_sco_refs.append(host_stix.id)
            enriched_objects.append(host_stix)
            enriched_objects.append(relationship)

        for file in report["extracted_files"]:
            if file["threat_level"] > 0:
                file_stix = stix2.File(
                    hashes={
                        "MD5": file["md5"],
                        "SHA-1": file["sha1"],
                        "SHA-256": file["sha256"],
                    },
                    size=file["size"],
                    name=file["name"],
                    object_marking_refs=[self.tlp],
                    custom_properties={
                        "x_opencti_created_by_ref": self.identity.id,
                        "x_opencti_labels": file["type_tags"],
                    },
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "drops", enriched_entity["id"], file_stix.id
                    ),
                    relationship_type="drops",
                    created_by_ref=self.identity.id,
                    source_ref=enriched_entity["id"],
                    target_ref=file_stix.id,
                )
                analysis_sco_refs.append(file_stix.id)
                enriched_objects.append(file_stix)
                enriched_objects.append(relationship)

        result_name = "Result " + opencti_entity["observable_value"]
        analysis_started = (
            datetime.now()
            if report["analysis_start_time"] is None
            else datetime.fromisoformat(report["analysis_start_time"])
        )
        external_reference = stix2.ExternalReference(
            source_name="Hybrid Analysis",
            url="https://www.hybrid-analysis.com/sample/" + report["sha256"],
            description="Hybrid Analysis Report",
        )
        malware_analysis = stix2.MalwareAnalysis(
            id=MalwareAnalysis.generate_id(result_name, "HybridAnalysis"),
            product="HybridAnalysis",
            result_name=result_name,
            analysis_started=analysis_started,
            submitted=datetime.now(),
            result=report["verdict"],
            sample_ref=enriched_entity["id"],
            created_by_ref=self.identity.id,
            operating_system_ref=(
                operating_system["id"] if operating_system is not None else None
            ),
            analysis_sco_refs=analysis_sco_refs,
            external_references=[external_reference],
        )
        enriched_objects.append(malware_analysis)

        return [self.identity, self.tlp] + enriched_objects

    def _get_report(self, report_id: str) -> dict:
        """Poll the Hybrid Analysis API until the report of submitted file is ready and return the report summary.
        :param report_id: The ID of the report to retrieve.
        :return: The report summary as a dictionary.
        :raises HybridAnalysisReportError: If the report processing resulted in an error.
        """
        state = None

        processing = True
        while processing:
            result = self.client.get_report_state(report_id)
            state = result["state"]
            if state in ["IN_QUEUE", "IN_PROGRESS"]:
                self.helper.connector_logger.debug(
                    "Report is still being processed, waiting 30 seconds before checking again.",
                    {"report_id": report_id, "state": state},
                )
                time.sleep(30)
            else:
                processing = False

        if state == "ERROR":
            raise HybridAnalysisReportError(result["error"])

        return self.client.get_report_summary(report_id)

    def _search_hash(self, opencti_entity: dict) -> dict | None:
        """
        Search for a file hash in the Hybrid Analysis database.
        :param opencti_entity: The OpenCTI representation of the entity being enriched.
        :return: The analysis report if found, else None.
        """
        hash_value = None
        for hash in opencti_entity["hashes"]:
            if hash["algorithm"] in ("SHA-256", "SHA-1", "MD5"):
                hash_value = hash["hash"]

        if hash_value is not None:
            result = self.client.search_hash(hash_value)
            if not result:
                self.helper.connector_logger.info(
                    "Hash not found in Hybrid Analysis database.",
                    {"hash": hash_value},
                )
                return None

            if len(result.get("reports", [])) > 0:
                self.helper.connector_logger.info(
                    "Hash analysis already exists in Hybrid Analysis, attaching knowledge..."
                )
                report = self.client.get_report_summary(result["reports"][0]["id"])
                return report

    def _submit_url(self, opencti_entity: dict) -> dict:
        """Submit a URL to the Hybrid Analysis sandbox for analysis.
        :param opencti_entity: The OpenCTI representation of the entity being enriched.
        :return: The analysis report.
        """

        self.helper.connector_logger.info(
            "Observable is a URL, triggering the sandbox..."
        )

        result = self.client.submit_url(opencti_entity["observable_value"])

        self.helper.connector_logger.info("Analysis in progress...")
        report = self._get_report(result["job_id"])
        self.helper.connector_logger.info("Analysis done, attaching knowledge...")
        return report

    def _trigger_sandbox(self, opencti_entity: dict) -> dict:
        """Submit a file to the Hybrid Analysis sandbox for analysis.
        :param opencti_entity: The OpenCTI representation of the entity being enriched.
        :return: The analysis report.
        """

        self.helper.connector_logger.info(
            "File not found in Hybrid Analysis, triggering the sandbox..."
        )

        file_name = opencti_entity["importFiles"][0]["name"]
        file_uri = opencti_entity["importFiles"][0]["id"]
        file_url = urljoin(str(self.config.opencti.url), f"storage/get/{file_uri}")
        file_content: bytes = self.helper.api.fetch_opencti_file(file_url, True)  # type: ignore[union-attr]

        result = self.client.submit_file(file_name, file_content)

        self.helper.connector_logger.info("Analysis in progress...")
        report = self._get_report(result["job_id"])
        self.helper.connector_logger.info("Analysis done, attaching knowledge...")
        return report

    def _process_observable(self, stix_entity: dict, opencti_entity: dict) -> str:
        """Process the observable based on its type and available data.
        :param stix_entity: The original STIX entity being enriched.
        :param opencti_entity: The OpenCTI representation of the entity being enriched.
        :return: A message indicating the result of the operation."""

        self.helper.connector_logger.info(
            "Processing the observable ",
            {
                "observable_type": opencti_entity["entity_type"],
                "observable_value": opencti_entity["observable_value"],
            },
        )

        report = None
        trigger_sandbox = False

        if opencti_entity["entity_type"] in ["Url", "Domain-Name", "Hostname"]:
            report = self._submit_url(opencti_entity)

        if opencti_entity["entity_type"] in ["StixFile", "Artifact"]:
            report = self._search_hash(opencti_entity)
            if report is None:
                trigger_sandbox = True

        if opencti_entity.get("importFiles"):
            trigger_sandbox = True

        if trigger_sandbox:
            report = self._trigger_sandbox(opencti_entity)

        if report is None:
            message = "Observable not found and no file to upload in the sandbox"
            self.helper.connector_logger.info(message)
            return message

        enriched_objects = self._create_knowledge(stix_entity, opencti_entity, report)
        bundles_sent = self._send_bundle(enriched_objects)

        message = f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        self.helper.connector_logger.info(message)
        return message

    def _send_bundle(
        self, stix_objects: list[stix2.v21._STIXBase21] | list[dict]
    ) -> list[str]:
        """Send a STIX bundle to OpenCTI.
        :param stix_objects: The list of STIX objects to include in the bundle.
        :return: List of the serialized bundle sent to OpenCTI.
        """
        if len(stix_objects) == 0:
            return []

        bundle = self.helper.stix2_create_bundle(stix_objects)
        return self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)  # type: ignore[union-attr]

    def _process_message(self, data: dict) -> str:
        """Process incoming message from OpenCTI.
        For playbook compatibility, the original bundle is sent back to OpenCTI in case of error during the enrichment process.
        :param data: The message data containing the STIX objects and entity information.
        :return: A message indicating the result of the operation.
        """
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        self.stix_objects = stix_objects
        original_stix_objects = deepcopy(stix_objects)  # save a copy in case of error

        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        try:
            if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
                self._send_bundle(original_stix_objects)

                message = "Do not send any data, TLP of the observable is greater than MAX TLP"
                self.helper.connector_logger.info(f"[CONNECTOR] {message}")
                return message

            return self._process_observable(stix_entity, opencti_entity)

        except (HybridAnalysisAPIError, HybridAnalysisReportError) as err:
            self.helper.connector_logger.error(
                f"[CONNECTOR] {err.__class__.__name__}: {str(err)}"
            )
            self._send_bundle(original_stix_objects)
            raise
        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] An unexpected error occurred",
                {"error": str(err)},
            )
            self._send_bundle(original_stix_objects)
            raise

    def start(self):
        """Start the connector by listening to messages from OpenCTI."""
        self.helper.listen(message_callback=self._process_message)

    def detect_ip_version(self, value):
        """Detect the IP version (IPv4 or IPv6) based on the length of the IP address string.
        :param value: The IP address string to analyze.
        :return: "IPv4-Addr" if the value is an IPv4 address, "IPv6-Addr" if it is an IPv6 address.
        """
        if len(value) > 16:
            return "IPv6-Addr"
        else:
            return "IPv4-Addr"
