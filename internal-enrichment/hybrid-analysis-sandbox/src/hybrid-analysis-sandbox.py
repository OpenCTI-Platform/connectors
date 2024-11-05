# coding: utf-8
import os
import sys
import time
from datetime import datetime
from typing import Dict

import requests
import stix2
import yaml
from pycti import (
    STIX_EXT_OCTI_SCO,
    AttackPattern,
    MalwareAnalysis,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from stix2 import DomainName, File, IPv4Address, IPv6Address


class HybridAnalysis:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)
        self.api_key = get_config_variable(
            "HYBRID_ANALYSIS_TOKEN", ["hybrid_analysis", "api_key"], config
        )
        self.environment_id = get_config_variable(
            "HYBRID_ANALYSIS_ENVIRONMENT_ID",
            ["hybrid_analysis", "environment_id"],
            config,
            True,
            110,
        )
        self.max_tlp = get_config_variable(
            "HYBRID_ANALYSIS_MAX_TLP", ["hybrid_analysis", "max_tlp"], config
        )
        self.api_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": self.api_key,
            "user-agent": "OpenCTI Hybrid Analysis Connector - Version 6.0.5",
            "accept": "application/json",
        }
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Hybrid Analysis",
            description="Hybrid Analysis Sandbox.",
        )["standard_id"]
        self._CONNECTOR_RUN_INTERVAL_SEC = 60 * 60

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
        # Sandbox Operating System
        operating_system = None
        if report["environment_id"] is not None:
            operating_system = stix2.Software(name=report["environment_description"])
            stix_objects.append(operating_system)
        # List of all the referenced SCO of the analysis
        analysis_sco_refs = []

        # Create external reference
        external_reference = stix2.ExternalReference(
            source_name="Hybrid Analysis",
            url="https://www.hybrid-analysis.com/sample/" + report["sha256"],
            description="Hybrid Analysis Report",
        )
        # Create tags
        for tag in report["type_short"]:
            self.helper.api.stix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "labels", tag, True
            )
        # Attach the TTPs
        for tactic in report["mitre_attcks"]:
            if (
                tactic["malicious_identifiers_count"] > 0
                or tactic["suspicious_identifiers_count"] > 0
            ):
                attack_pattern = stix2.AttackPattern(
                    id=AttackPattern.generate_id(
                        tactic["technique"], tactic["attck_id"]
                    ),
                    created_by_ref=self.identity,
                    name=tactic["technique"],
                    custom_properties={
                        "x_mitre_id": tactic["attck_id"],
                    },
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_entity["id"], attack_pattern.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=stix_entity["id"],
                    target_ref=attack_pattern.id,
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                stix_objects.append(attack_pattern)
                stix_objects.append(relationship)
        # Attach the domains
        for domain in report["domains"]:
            if domain != opencti_entity["observable_value"]:
                domain_stix = DomainName(
                    value=domain,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "created_by_ref": self.identity,
                    },
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_entity["id"], domain_stix.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=stix_entity["id"],
                    target_ref=domain_stix.id,
                    object_marking_refs=[stix2.TLP_WHITE],
                    confidence=self.helper.connect_confidence_level,
                )
                # Attach IP to Malware Analysis (through analysis_sco_refs)
                analysis_sco_refs.append(domain_stix.id)
                stix_objects.append(domain_stix)
                stix_objects.append(relationship)
        # Attach the IP addresses
        for host in report["hosts"]:
            if self.detect_ip_version(host) == "IPv4-Addr":
                host_stix = IPv4Address(
                    value=host,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "created_by_ref": self.identity,
                    },
                )
            else:
                host_stix = IPv6Address(
                    value=host,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "created_by_ref": self.identity,
                    },
                )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", stix_entity["id"], host_stix.id
                ),
                relationship_type="related-to",
                created_by_ref=self.identity,
                source_ref=stix_entity["id"],
                target_ref=host_stix.id,
                object_marking_refs=[stix2.TLP_WHITE],
                confidence=self.helper.connect_confidence_level,
            )
            # Attach IP to Malware Analysis (through analysis_sco_refs)
            analysis_sco_refs.append(host_stix.id)
            stix_objects.append(host_stix)
            stix_objects.append(relationship)
        # Attach other files
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
                    created_by_ref=self.identity,
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "drops", stix_entity["id"], file_stix.id
                    ),
                    relationship_type="drops",
                    created_by_ref=self.identity,
                    source_ref=stix_entity["id"],
                    target_ref=file_stix.id,
                    confidence=self.helper.connect_confidence_level,
                )
                # Attach file to Malware Analysis (through analysis_sco_refs)
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
                    created_by_ref=self.identity,
                    name=tactic["technique"],
                    confidence=self.helper.connect_confidence_level,
                    custom_properties={
                        "x_mitre_id": tactic["attck_id"],
                    },
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_entity["id"], attack_pattern.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=stix_entity["id"],
                    target_ref=attack_pattern.id,
                )
                stix_objects.append(attack_pattern)
                stix_objects.append(relationship)
        # Creating the Malware Analysis
        result_name = "Result " + opencti_entity["observable_value"]
        analysis_started = (
            datetime.now()
            if report["analysis_start_time"] is None
            else datetime.strptime(
                report["analysis_start_time"], "%Y-%m-%dT%H:%M:%S+00:00"
            )
        )
        malware_analysis = stix2.MalwareAnalysis(
            id=MalwareAnalysis.generate_id(result_name),
            product="HybridAnalysis",
            result_name=result_name,
            analysis_started=analysis_started,
            submitted=datetime.now(),
            result=report["verdict"],
            sample_ref=stix_entity["id"],
            created_by_ref=self.identity,
            operating_system_ref=(
                operating_system["id"] if operating_system is not None else None
            ),
            analysis_sco_refs=analysis_sco_refs,
            external_references=[external_reference],
        )
        stix_objects.append(malware_analysis)
        if len(stix_objects) > 0:
            serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
            bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            return (
                "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
            )
        else:
            return "Nothing to attach"

    def _submit_url(self, stix_objects, stix_entity, opencti_entity):
        self.helper.log_info("Observable is a URL, triggering the sandbox...")
        values = {
            "url": opencti_entity["observable_value"],
            "environment_id": self.environment_id,
        }
        r = requests.post(
            self.api_url + "/submit/url",
            headers=self.headers,
            data=values,
        )
        if r.status_code > 299:
            raise ValueError(r.text)
        result = r.json()
        job_id = result["job_id"]
        state = "IN_QUEUE"
        self.helper.log_info("Analysis in progress...")
        while state == "IN_QUEUE" or state == "IN_PROGRESS":
            r = requests.get(
                self.api_url + "/report/" + job_id + "/state",
                headers=self.headers,
            )
            if r.status_code > 299:
                raise ValueError(r.text)
            result = r.json()
            state = result["state"]
            time.sleep(30)
        if state == "ERROR":
            raise ValueError(result["error"])
        r = requests.get(
            self.api_url + "/report/" + job_id + "/summary",
            headers=self.headers,
        )
        if r.status_code > 299:
            raise ValueError(r.text)
        result = r.json()
        self.helper.log_info("Analysis done, attaching knowledge...")
        return self._send_knowledge(stix_objects, stix_entity, opencti_entity, result)

    def _trigger_sandbox(self, stix_objects, stix_entity, opencti_entity):
        self.helper.log_info("File not found in HA, triggering the sandbox...")
        file_name = opencti_entity["importFiles"][0]["name"]
        file_uri = opencti_entity["importFiles"][0]["id"]
        file_content = self.helper.api.fetch_opencti_file(
            self.helper.opencti_url + "/storage/get/" + file_uri, True
        )
        # Write the file
        f = open(file_name, "wb")
        f.write(file_content)
        f.close()
        with open(file_name, "rb") as f:
            values = {"environment_id": self.environment_id}
            r = requests.post(
                self.api_url + "/submit/file",
                headers=self.headers,
                files={"file": (file_name, f)},
                data=values,
            )
            f.close()
        os.remove(file_name)
        if r.status_code > 299:
            raise ValueError(r.text)
        result = r.json()
        job_id = result["job_id"]
        state = "IN_QUEUE"
        self.helper.log_info("Analysis in progress...")
        while state == "IN_QUEUE" or state == "IN_PROGRESS":
            r = requests.get(
                self.api_url + "/report/" + job_id + "/state",
                headers=self.headers,
            )
            if r.status_code > 299:
                raise ValueError(r.text)
            result = r.json()
            state = result["state"]
            time.sleep(30)
        if state == "ERROR":
            raise ValueError(result["error"])
        r = requests.get(
            self.api_url + "/report/" + job_id + "/summary",
            headers=self.headers,
        )
        if r.status_code > 299:
            raise ValueError(r.text)
        result = r.json()
        self.helper.log_info("Analysis done, attaching knowledge...")
        return self._send_knowledge(stix_objects, stix_entity, opencti_entity, result)

    def _process_observable(self, stix_objects, stix_entity, opencti_entity):
        self.helper.log_info(
            "Processing the observable " + opencti_entity["observable_value"]
        )
        # If File or Artifact
        result = []
        if opencti_entity["entity_type"] in ["StixFile", "Artifact"]:
            # First, check if the file is present is HA
            values = None
            for hash in opencti_entity["hashes"]:
                if hash["algorithm"] == "SHA-256":
                    values = {"hash": hash["hash"]}
                elif hash["algorithm"] == "SHA-1":
                    values = {"hash": hash["hash"]}
                elif hash["algorithm"] == "MD5":
                    values = {"hash": hash["hash"]}
            if values is not None:
                r = requests.post(
                    self.api_url + "/search/hash",
                    headers=self.headers,
                    data=values,
                )
                if r.status_code > 299:
                    raise ValueError(r.text)
                result = r.json()
        if len(result) > 0:
            # One report is found
            self.helper.log_info("Already found in HA, attaching knowledge...")
            return self._send_knowledge(
                stix_objects, stix_entity, opencti_entity, result[0]
            )
        # If URL
        if opencti_entity["entity_type"] in ["Url", "Domain-Name", "Hostname"]:
            return self._submit_url(stix_objects, stix_entity, opencti_entity)
        # If no file
        if (
            "importFiles" not in opencti_entity
            or len(opencti_entity["importFiles"]) == 0
        ):
            return "Observable not found and no file to upload in the sandbox"
        return self._trigger_sandbox(stix_objects, stix_entity, opencti_entity)

    def _process_message(self, data: Dict):
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        return self._process_observable(stix_objects, stix_entity, opencti_entity)

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)

    def detect_ip_version(self, value):
        if len(value) > 16:
            return "IPv6-Addr"
        else:
            return "IPv4-Addr"


if __name__ == "__main__":
    try:
        hybridAnalysis = HybridAnalysis()
        hybridAnalysis.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
