# coding: utf-8
import os
import sys
import time
from datetime import datetime

import requests
import stix2
import yaml
from pycti import (
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
        self.helper = OpenCTIConnectorHelper(config)
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
            "user-agent": "OpenCTI Hybrid Analysis Connector - Version 5.8.4",
            "accept": "application/json",
        }
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Hybrid Analysis",
            description="Hybrid Analysis Sandbox.",
        )["standard_id"]
        self._CONNECTOR_RUN_INTERVAL_SEC = 60 * 60

    def _send_knowledge(self, observable, report):
        bundle_objects = []
        final_observable = observable
        if observable["entity_type"] in ["StixFile", "Artifact"]:
            if report["md5"] is not None:
                final_observable = self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    input={"key": "hashes.MD5", "value": report["md5"]},
                )
            if report["sha1"] is not None:
                final_observable = self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    input={"key": "hashes.SHA-1", "value": report["sha1"]},
                )
            if report["sha256"] is not None:
                final_observable = self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    input={
                        "key": "hashes.SHA-256",
                        "value": report["sha256"],
                    },
                )
            if "name" not in final_observable or final_observable["name"] is None:
                self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    input={
                        "key": "x_opencti_additional_names",
                        "value": report["submit_name"],
                        "operation": "add",
                    },
                )
            if final_observable["entity_type"] == "StixFile":
                self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    input={"key": "size", "value": str(report["size"])},
                )
        self.helper.api.stix_cyber_observable.update_field(
            id=final_observable["id"],
            input={"key": "x_opencti_score", "value": str(report["threat_score"])},
        )
        # Sandbox Operating System
        if report["environment_id"] is not None:
            operating_system = stix2.Software(name=report["environment_description"])
            bundle_objects.append(operating_system)
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
            tag_ha = self.helper.api.label.create(value=tag, color="#0059f7")
            self.helper.api.stix_cyber_observable.add_label(
                id=final_observable["id"], label_id=tag_ha["id"]
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
                        "related-to", final_observable["standard_id"], attack_pattern.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=final_observable["standard_id"],
                    target_ref=attack_pattern.id,
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                bundle_objects.append(attack_pattern)
                bundle_objects.append(relationship)
        # Attach the domains
        for domain in report["domains"]:
            if domain != final_observable["value"]:
                domain_stix = DomainName(
                    value=domain,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "created_by_ref": self.identity,
                    },
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", final_observable["standard_id"], domain_stix.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=final_observable["standard_id"],
                    target_ref=domain_stix.id,
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                # Attach IP to Malware Analysis (through analysis_sco_refs)
                analysis_sco_refs.append(domain_stix.id)
                bundle_objects.append(domain_stix)
                bundle_objects.append(relationship)
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
                    "related-to", final_observable["standard_id"], host_stix.id
                ),
                relationship_type="related-to",
                created_by_ref=self.identity,
                source_ref=final_observable["standard_id"],
                target_ref=host_stix.id,
                object_marking_refs=[stix2.TLP_WHITE],
            )
            # Attach IP to Malware Analysis (through analysis_sco_refs)
            analysis_sco_refs.append(host_stix.id)
            bundle_objects.append(host_stix)
            bundle_objects.append(relationship)
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
                        "drops", final_observable["standard_id"], file_stix.id
                    ),
                    relationship_type="drops",
                    created_by_ref=self.identity,
                    source_ref=final_observable["standard_id"],
                    target_ref=file_stix.id,
                )
                # Attach file to Malware Analysis (through analysis_sco_refs)
                analysis_sco_refs.append(file_stix.id)

                bundle_objects.append(file_stix)
                bundle_objects.append(relationship)
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
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", final_observable["standard_id"], attack_pattern.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=final_observable["standard_id"],
                    target_ref=attack_pattern.id,
                )
                bundle_objects.append(attack_pattern)
                bundle_objects.append(relationship)
        # Creating the Malware Analysis
        result_name = "Result " + observable["observable_value"]
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
            sample_ref=final_observable["standard_id"],
            created_by_ref=self.identity,
            operating_system_ref=operating_system["id"]
            if "operating_system" in locals()
            else None,
            analysis_sco_refs=analysis_sco_refs,
            external_references=[external_reference],
        )
        bundle_objects.append(malware_analysis)
        if len(bundle_objects) > 0:
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return (
                "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
            )
        else:
            return "Nothing to attach"

    def _submit_url(self, observable):
        self.helper.log_info("Observable is a URL, triggering the sandbox...")
        values = {
            "url": observable["observable_value"],
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
        return self._send_knowledge(observable, result)

    def _trigger_sandbox(self, observable):
        self.helper.log_info("File not found in HA, triggering the sandbox...")
        file_name = observable["importFiles"][0]["name"]
        file_uri = observable["importFiles"][0]["id"]
        file_content = self.helper.api.fetch_opencti_file(self.api_url + file_uri, True)
        # Write the file
        f = open(file_name, "wb")
        f.write(file_content)
        f.close()
        files = {"file": open(file_name, "rb")}
        values = {"environment_id": self.environment_id}
        r = requests.post(
            self.api_url + "/submit/file",
            headers=self.headers,
            files=files,
            data=values,
        )
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
        return self._send_knowledge(observable, result)

    def _process_observable(self, observable):
        self.helper.log_info(
            "Processing the observable " + observable["observable_value"]
        )
        # If File or Artifact
        result = []
        if observable["entity_type"] in ["StixFile", "Artifact"]:
            # First, check if the file is present is HA
            values = {"hash": observable["observable_value"]}
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
            return self._send_knowledge(observable, result[0])
        # If URL
        if observable["entity_type"] in ["Url", "Domain-Name", "Hostname"]:
            return self._submit_url(observable)
        # If no file
        if "importFiles" not in observable or len(observable["importFiles"]) == 0:
            return "Observable not found and no file to upload in the sandbox"
        return self._trigger_sandbox(observable)

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable not found "
                "(may be linked to data seggregation, check your group and permissions)"
            )

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        return self._process_observable(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)

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
