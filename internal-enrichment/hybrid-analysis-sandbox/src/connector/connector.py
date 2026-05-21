import time
from datetime import datetime
from urllib.parse import urljoin

import stix2
from connector.settings import ConnectorSettings
from pycti import (
    Identity,
    STIX_EXT_OCTI_SCO,
    AttackPattern,
    MalwareAnalysis,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from stix2 import DomainName, File, IPv4Address, IPv6Address


class TLPExceededError(ValueError):
    """Raised when the TLP of the observable is greater than the maximum TLP allowed for enrichment."""

    pass


class HybridAnalysis:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.api_key = self.config.hybrid_analysis_sandbox.token.get_secret_value()
        self.environment_id = self.config.hybrid_analysis_sandbox.environment_id

        self.client = HybridAnalysisClient(
            helper,
            token=self.config.hybrid_analysis_sandbox.token.get_secret_value(),
            environment_id=self.config.hybrid_analysis_sandbox.environment_id,
        )

        self.max_tlp = self.config.hybrid_analysis_sandbox.max_tlp

        self.identity = stix2.Identity(
            id=Identity.generate_id(
                name="Hybrid Analysis", identity_class="organization"
            ),
            name="Hybrid Analysis",
            identity_class="organization",
            description="Hybrid Analysis Sandbox.",
        )

    def _send_knowledge(self, stix_objects, stix_entity, opencti_entity, report):
        if opencti_entity["entity_type"] in ["StixFile", "Artifact"]:
            if report["md5"] is not None:
                stix_entity["hashes"]["MD5"] = report["md5"]
            if report["sha1"] is not None:
                stix_entity["hashes"]["SHA-1"] = report["sha1"]
            if report["sha256"] is not None:
                stix_entity["hashes"]["SHA-256"] = report["sha256"]
            self.helper.api.stix2.put_attribute_in_extension(
                stix_entity,
                STIX_EXT_OCTI_SCO,
                "additional_names",
                report["submit_name"],
                True,
            )
            if opencti_entity["entity_type"] == "StixFile":
                stix_entity["size"] = report["size"]
        self.helper.api.stix2.put_attribute_in_extension(
            stix_entity, STIX_EXT_OCTI_SCO, "score", report["threat_score"]
        )
        operating_system = None
        if report["environment_id"] is not None:
            operating_system = stix2.Software(name=report["environment_description"])
            stix_objects.append(operating_system)
        analysis_sco_refs = []
        external_reference = stix2.ExternalReference(
            source_name="Hybrid Analysis",
            url="https://www.hybrid-analysis.com/sample/" + report["sha256"],
            description="Hybrid Analysis Report",
        )
        for tag in report["type_short"]:
            self.helper.api.stix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "labels", tag, True
            )
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
                        "related-to", stix_entity["id"], attack_pattern.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity.id,
                    source_ref=stix_entity["id"],
                    target_ref=attack_pattern.id,
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                stix_objects.append(attack_pattern)
                stix_objects.append(relationship)
        for domain in report["domains"]:
            if domain != opencti_entity["observable_value"]:
                domain_stix = DomainName(
                    value=domain,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={"created_by_ref": self.identity.id},
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_entity["id"], domain_stix.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity.id,
                    source_ref=stix_entity["id"],
                    target_ref=domain_stix.id,
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                analysis_sco_refs.append(domain_stix.id)
                stix_objects.append(domain_stix)
                stix_objects.append(relationship)
        for host in report["hosts"]:
            if self.detect_ip_version(host) == "IPv4-Addr":
                host_stix = IPv4Address(
                    value=host,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={"created_by_ref": self.identity.id},
                )
            else:
                host_stix = IPv6Address(
                    value=host,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={"created_by_ref": self.identity.id},
                )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", stix_entity["id"], host_stix.id
                ),
                relationship_type="related-to",
                created_by_ref=self.identity.id,
                source_ref=stix_entity["id"],
                target_ref=host_stix.id,
                object_marking_refs=[stix2.TLP_WHITE],
            )
            analysis_sco_refs.append(host_stix.id)
            stix_objects.append(host_stix)
            stix_objects.append(relationship)
        for file in report["extracted_files"]:
            if file["threat_level"] > 0:
                file_stix = File(
                    hashes={
                        "MD5": file["md5"],
                        "SHA-1": file["sha1"],
                        "SHA-256": file["sha256"],
                    },
                    size=file["size"],
                    name=file["name"],
                    custom_properties={"x_opencti_labels": file["type_tags"]},
                    created_by_ref=self.identity.id,
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "drops", stix_entity["id"], file_stix.id
                    ),
                    relationship_type="drops",
                    created_by_ref=self.identity.id,
                    source_ref=stix_entity["id"],
                    target_ref=file_stix.id,
                )
                analysis_sco_refs.append(file_stix.id)
                stix_objects.append(file_stix)
                stix_objects.append(relationship)
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
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_entity["id"], attack_pattern.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity.id,
                    source_ref=stix_entity["id"],
                    target_ref=attack_pattern.id,
                )
                stix_objects.append(attack_pattern)
                stix_objects.append(relationship)
        result_name = "Result " + opencti_entity["observable_value"]
        analysis_started = (
            datetime.now()
            if report["analysis_start_time"] is None
            else datetime.strptime(
                report["analysis_start_time"], "%Y-%m-%dT%H:%M:%S+00:00"
            )
        )
        malware_analysis = stix2.MalwareAnalysis(
            id=MalwareAnalysis.generate_id(result_name, "HybridAnalysis"),
            product="HybridAnalysis",
            result_name=result_name,
            analysis_started=analysis_started,
            submitted=datetime.now(),
            result=report["verdict"],
            sample_ref=stix_entity["id"],
            created_by_ref=self.identity.id,
            operating_system_ref=(
                operating_system["id"] if operating_system is not None else None
            ),
            analysis_sco_refs=analysis_sco_refs,
            external_references=[external_reference],
        )
        stix_objects.append(malware_analysis)
        if len(stix_objects) > 0:
            serialized_bundle = self.helper.stix2_create_bundle(
                [self.identity] + stix_objects
            )
            if not serialized_bundle:
                return "Nothing to attach"
            bundles_sent = self.helper.send_stix2_bundle(
                serialized_bundle, cleanup_inconsistent_bundle=True
            )
            return (
                "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
            )
        else:
            return "Nothing to attach"

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


    def _process_message(self, data: Dict):
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        try:
            if OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
                return self._process_observable(
                    stix_objects, stix_entity, opencti_entity
                )

            raise TLPExceededError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        except Exception as err:
            if isinstance(err, TLPExceededError):
                self.helper.connector_logger.info(f"[CONNECTOR] {str(err)}")
            else:
                self.helper.connector_logger.error(
                    "[CONNECTOR] An unexpected error occurred",
                    {"error": str(err)},
                )

            # Send the original bundle if the connector has been triggered by a playbook
            event_type = data.get("event_type")
            if not event_type:
                self.helper.stix2_create_bundle(stix_objects)

            raise err

    def start(self):
        self.helper.listen(message_callback=self._process_message)

    def detect_ip_version(self, value):
        if len(value) > 16:
            return "IPv6-Addr"
        else:
            return "IPv4-Addr"
