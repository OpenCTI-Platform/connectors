# coding: utf-8

import os
import yaml
import requests
import time

from stix2 import (
    Bundle,
    AttackPattern,
    Relationship,
    File,
    TLP_WHITE,
)
from pycti import (
    OpenCTIConnectorHelper,
    OpenCTIStix2Utils,
    get_config_variable,
    SimpleObservable,
)


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
            "user-agent": "OpenCTI Hybrid Analysis Connector - Version 5.1.1",
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
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=final_observable["id"],
                input={"key": "hashes.MD5", "value": report["md5"]},
            )
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=final_observable["id"],
                input={"key": "hashes.SHA-1", "value": report["sha1"]},
            )
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
        # Create external reference
        external_reference = self.helper.api.external_reference.create(
            source_name="Hybrid Analysis",
            url="https://www.hybrid-analysis.com/sample/" + report["sha256"],
            description="Hybrid Analysis Report",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=final_observable["id"],
            external_reference_id=external_reference["id"],
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
                attack_pattern = AttackPattern(
                    id=OpenCTIStix2Utils.generate_random_stix_id("attack-pattern"),
                    created_by_ref=self.identity,
                    name=tactic["technique"],
                    custom_properties={
                        "x_mitre_id": tactic["attck_id"],
                    },
                    object_marking_refs=[TLP_WHITE],
                )
                relationship = Relationship(
                    id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                    relationship_type="uses",
                    created_by_ref=self.identity,
                    source_ref=final_observable["standard_id"],
                    target_ref=attack_pattern.id,
                    object_marking_refs=[TLP_WHITE],
                )
                bundle_objects.append(attack_pattern)
                bundle_objects.append(relationship)
        # Attach the domains
        for domain in report["domains"]:
            domain_stix = SimpleObservable(
                id=OpenCTIStix2Utils.generate_random_stix_id(
                    "x-opencti-simple-observable"
                ),
                key="Domain-Name.value",
                value=domain,
                created_by_ref=self.identity,
                object_marking_refs=[TLP_WHITE],
            )
            relationship = Relationship(
                id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                relationship_type="communicates-with",
                created_by_ref=self.identity,
                source_ref=final_observable["standard_id"],
                target_ref=domain_stix.id,
                object_marking_refs=[TLP_WHITE],
            )
            bundle_objects.append(domain_stix)
            bundle_objects.append(relationship)
        # Attach the IP addresses
        for host in report["hosts"]:
            host_stix = SimpleObservable(
                id=OpenCTIStix2Utils.generate_random_stix_id(
                    "x-opencti-simple-observable"
                ),
                key=self.detect_ip_version(host) + ".value",
                value=host,
                created_by_ref=self.identity,
                object_marking_refs=[TLP_WHITE],
            )
            relationship = Relationship(
                id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                relationship_type="communicates-with",
                created_by_ref=self.identity,
                source_ref=final_observable["standard_id"],
                target_ref=host_stix.id,
                object_marking_refs=[TLP_WHITE],
            )
            bundle_objects.append(host_stix)
            bundle_objects.append(relationship)
        # Attach other files
        for file in report["extracted_files"]:
            if file["threat_level"] > 0:
                file_stix = File(
                    id=OpenCTIStix2Utils.generate_random_stix_id("file"),
                    hashes={
                        "MD5": file["md5"],
                        "SHA-1": file["sha1"],
                        "SHA-256": file["sha256"],
                    },
                    size=file["size"],
                    name=file["name"],
                    custom_properties={"x_opencti_labels": file["type_tags"]},
                    created_by_ref=self.identity,
                    object_marking_refs=[TLP_WHITE],
                )
                relationship = Relationship(
                    id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                    relationship_type="drops",
                    created_by_ref=self.identity,
                    source_ref=final_observable["standard_id"],
                    target_ref=file_stix.id,
                )
                bundle_objects.append(file_stix)
                bundle_objects.append(relationship)
        for tactic in report["mitre_attcks"]:
            if (
                tactic["malicious_identifiers_count"] > 0
                or tactic["suspicious_identifiers_count"] > 0
            ):
                attack_pattern = AttackPattern(
                    id=OpenCTIStix2Utils.generate_random_stix_id("attack-pattern"),
                    created_by_ref=self.identity,
                    name=tactic["technique"],
                    custom_properties={
                        "x_mitre_id": tactic["attck_id"],
                    },
                )
                relationship = Relationship(
                    id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                    relationship_type="uses",
                    created_by_ref=self.identity,
                    source_ref=final_observable["standard_id"],
                    target_ref=attack_pattern.id,
                )
                bundle_objects.append(attack_pattern)
                bundle_objects.append(relationship)
        if len(bundle_objects) > 0:
            bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
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
        if observable["entity_type"] in ["Url", "Domain-Name", "X-OpenCTI-Hostname"]:
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
        tlp = "TLP:WHITE"
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
        exit(0)
