# coding: utf-8
import datetime
import io
import json
import os
import re
import sys
import time
from typing import Dict
from urllib.parse import urlparse

import magic
import pyzipper
import requests
import stix2
import yaml
from pycti import (
    AttackPattern,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from stix2 import DomainName, IPv4Address


class CapeSandboxConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="CAPEv2 Sandbox",
            description="CAPEv2 Sandbox.",
        )["standard_id"]

        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.cape_api_url = get_config_variable(
            "CAPE_SANDBOX_URL", ["cape_sandbox", "url"], config
        )
        self.token = get_config_variable(
            "CAPE_SANDBOX_TOKEN", ["cape_sandbox", "token"], config
        )
        self.max_tlp = get_config_variable(
            "CAPE_SANDBOX_MAX_TLP", ["cape_sandbox", "max_tlp"], config
        )
        self.less_noise = get_config_variable(
            "CAPE_SANDBOX_LESS_NOISE", ["cape_sandbox", "less_noise"], config
        )
        self._cooldown_time = get_config_variable(
            "CAPE_SANDBOX_COOLDOWN_TIME", ["cape_sandbox", "cooldown_time"], config
        )
        self._max_retries = get_config_variable(
            "CAPE_SANDBOX_MAX_RETRIES",
            ["cape_sandbox", "max_retries"],
            config,
            default=10,
            isNumber=True,
        )

        self.headers = {"Authorization": f"Token {self.token}"}

        # Analysis options

        self.route = get_config_variable(
            "CAPE_SANDBOX_ROUTE", ["cape_sandbox", "route"], config
        )

        self.try_extract = get_config_variable(
            "CAPE_SANDBOX_TRY_EXTRACT", ["cape_sandbox", "try_extract"], config
        )

        self.options = get_config_variable(
            "CAPE_SANDBOX_OPTIONS", ["cape_sandbox", "options"], config
        )

        self.timeout = get_config_variable(
            "CAPE_SANDBOX_TIMEOUT", ["cape_sandbox", "timeout"], config
        )

        self.enforce_timeout = get_config_variable(
            "CAPE_SANDBOX_ENFORCE_TIMEOUT", ["cape_sandbox", "enforce_timeout"], config
        )

        self.priority = get_config_variable(
            "CAPE_SANDBOX_PRIORITY", ["cape_sandbox", "priority"], config
        )

    def _send_knowledge(self, observable, report):
        bundle_objects = []
        final_observable = observable

        target = report["target"]["file"]
        task_id = report["info"]["id"]

        final_observable = self.helper.api.stix_cyber_observable.update_field(
            id=final_observable["id"],
            input={
                "key": "hashes",
                "object_path": "/hashes/MD5",
                "value": target["md5"],
            },
        )
        final_observable = self.helper.api.stix_cyber_observable.update_field(
            id=final_observable["id"],
            input={
                "key": "hashes",
                "object_path": "/hashes/SHA-1",
                "value": target["sha1"],
            },
        )
        final_observable = self.helper.api.stix_cyber_observable.update_field(
            id=final_observable["id"],
            input={
                "key": "hashes",
                "object_path": "/hashes/SHA-256",
                "value": target["sha256"],
            },
        )

        self.helper.api.stix_cyber_observable.update_field(
            id=final_observable["id"],
            input={
                "key": "x_opencti_score",
                "value": str(int(report["malscore"] * 10)),
            },
        )

        # Create external references
        # Analysis URL
        external_reference = self.helper.api.external_reference.create(
            source_name="CAPEv2 Sandbox Analysis",
            url=f"{self.cape_api_url}/analysis/{task_id}/",
            description="CAPEv2 Sandbox Analysis",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=final_observable["id"],
            external_reference_id=external_reference["id"],
        )
        # JSON report
        external_reference = self.helper.api.external_reference.create(
            source_name="CAPEv2 Sandbox JSON Report",
            url=f"{self.cape_api_url}/filereport/{task_id}/json/",
            description="CAPEv2 Sandbox JSON Report",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=final_observable["id"],
            external_reference_id=external_reference["id"],
        )
        # HTML Report
        external_reference = self.helper.api.external_reference.create(
            source_name="CAPEv2 Sandbox HTML Report",
            url=f"{self.cape_api_url}/filereport/{task_id}/html/",
            description="CAPEv2 Sandbox HTML Report",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=final_observable["id"],
            external_reference_id=external_reference["id"],
        )

        # Create label if family was detected
        if "detections" in report and report["detections"]:
            label = self.helper.api.label.create(
                value=report["detections"], color="#0059f7"
            )
            self.helper.api.stix_cyber_observable.add_label(
                id=final_observable["id"], label_id=label["id"]
            )

        # Create a Note containing the TrID results

        trid_json = None
        if report.get("trid"):
            trid_json = json.dumps(report["trid"], indent=2)
        elif target.get("trid"):
            trid_json = json.dumps(target["trid"], indent=2)
        if trid_json:
            note = stix2.Note(
                id=Note.generate_id(
                    datetime.datetime.now().isoformat(), f"```\n{trid_json}\n```"
                ),
                abstract="TrID Analysis",
                content=f"```\n{trid_json}\n```",
                created_by_ref=self.identity,
                object_refs=[final_observable["standard_id"]],
            )
            bundle_objects.append(note)

        # Attach the TTPs
        for tactic_dict in report["ttps"]:
            attack_id = tactic_dict["ttp"]
            signature = tactic_dict["signature"]

            attack_pattern = stix2.AttackPattern(
                id=AttackPattern.generate_id(signature, attack_id),
                created_by_ref=self.identity,
                name=signature,
                custom_properties={
                    "x_mitre_id": attack_id,
                },
                object_marking_refs=[stix2.TLP_WHITE],
            )

            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "uses", final_observable["standard_id"], attack_pattern.id
                ),
                relationship_type="uses",
                created_by_ref=self.identity,
                source_ref=final_observable["standard_id"],
                target_ref=attack_pattern.id,
                object_marking_refs=[stix2.TLP_WHITE],
            )
            bundle_objects.append(attack_pattern)
            bundle_objects.append(relationship)

        # Handle procdumps and attach any Flare CAPA TTPs
        if "procdump" in report and report["procdump"]:
            # Download the zip archive of procdump files
            zip_contents = self._get_procdump_zip(task_id)
            zip_obj = io.BytesIO(zip_contents)

            # Extract with "infected" password
            zip_file = pyzipper.AESZipFile(zip_obj)
            zip_file.setpassword(b"infected")

            # Process each entry in the procdump key
            for procdump_dict in report["procdump"]:
                # If less noise was specified
                if self.less_noise:
                    # and no Yara matches, skip this procdump
                    if not procdump_dict["cape_yara"] or not procdump_dict["yara"]:
                        continue

                sha256 = procdump_dict["sha256"]
                cape_type = procdump_dict["cape_type"]
                module_path = procdump_dict["module_path"]
                procdump_contents = zip_file.read(sha256)
                mime_type = magic.from_buffer(procdump_contents, mime=True)

                kwargs = {
                    "file_name": module_path,
                    "data": procdump_contents,
                    "mime_type": mime_type,
                    "x_opencti_description": cape_type,
                }
                response = self.helper.api.stix_cyber_observable.upload_artifact(
                    **kwargs
                )
                self.helper.log_info(
                    f'Uploaded procdump with sha256 "{sha256}" and type "{cape_type}".'
                )

                # Build labels
                yara_rules = []
                cape_yara_rules = []
                yara_rules.extend(
                    [yara_dict["name"] for yara_dict in procdump_dict["yara"]]
                )
                cape_yara_rules.extend(
                    [yara_dict["name"] for yara_dict in procdump_dict["cape_yara"]]
                )
                cape_yara_rules.extend(
                    [
                        yara_dict["meta"]["cape_type"]
                        for yara_dict in procdump_dict["cape_yara"]
                    ]
                )

                # Create and apply yara rule based labels
                for yara_rule in yara_rules:
                    label = self.helper.api.label.create(
                        value=yara_rule, color="#0059f7"
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=response["id"], label_id=label["id"]
                    )

                # Create and apply cape yara rule based labels
                for cape_yara_rule in cape_yara_rules:
                    label = self.helper.api.label.create(
                        value=cape_yara_rule, color="#ff8178"
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=response["id"], label_id=label["id"]
                    )

                # Create label for cape_type
                label = self.helper.api.label.create(value=cape_type, color="#0059f7")
                self.helper.api.stix_cyber_observable.add_label(
                    id=response["id"], label_id=label["id"]
                )

                # Create relationship between uploaded procdump Artifact and original
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        response["standard_id"],
                        final_observable["standard_id"],
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=response["standard_id"],
                    target_ref=final_observable["standard_id"],
                )
                bundle_objects.append(relationship)

                # Handle Flare CAPA TTPs
                if "flare_capa" in procdump_dict and procdump_dict["flare_capa"]:
                    attck_dict = procdump_dict["flare_capa"]["ATTCK"]
                    for tactic in attck_dict:
                        tp_list = attck_dict[tactic]
                        for tp in tp_list:
                            attack_pattern = stix2.AttackPattern(
                                id=AttackPattern.generate_id(tactic, tp),
                                created_by_ref=self.identity,
                                name=tactic,
                                custom_properties={
                                    "x_mitre_id": tp,
                                },
                                object_marking_refs=[stix2.TLP_WHITE],
                            )

                            relationship = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "uses", response["standard_id"], attack_pattern.id
                                ),
                                relationship_type="uses",
                                created_by_ref=self.identity,
                                source_ref=response["standard_id"],
                                target_ref=attack_pattern.id,
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            bundle_objects.append(attack_pattern)
                            bundle_objects.append(relationship)

                else:
                    self.helper.log_info(
                        f"Could not find flare_capa key or was empty in procdump {sha256}."
                    )

            # Close the zip file
            zip_file.close()

        else:
            self.helper.log_info(
                "Skipping processing process dumps, procdump key is empty or not exists."
            )

        # Attach CnC addresses if any configs were found
        if "CAPE" in report and report["CAPE"]["configs"]:
            configs_list = report["CAPE"]["configs"]
            for config_dict in configs_list:
                for detection_name in config_dict:
                    # Create a Note containing the config
                    note = stix2.Note(
                        abstract=f"{detection_name} Config",
                        content=f"```\n{json.dumps(config_dict, indent=2)}\n```",
                        created_by_ref=self.identity,
                        object_refs=[final_observable["standard_id"]],
                    )
                    bundle_objects.append(note)

                    if "address" not in config_dict[detection_name]:
                        self.helper.log_info(
                            f'Could not find an "address" key in {detection_name} config.'
                        )
                        continue

                    address_list = config_dict[detection_name]["address"]
                    for address in address_list:
                        parsed = address.rsplit(":", 1)[0]
                        if self._is_ipv4_address(parsed):
                            host_stix = IPv4Address(
                                value=parsed,
                                object_marking_refs=[stix2.TLP_WHITE],
                                custom_properties={
                                    "labels": [detection_name, "c2 server"],
                                    "created_by_ref": self.identity,
                                },
                            )
                            relationship = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "communicates-with",
                                    final_observable["standard_id"],
                                    host_stix.id,
                                ),
                                relationship_type="communicates-with",
                                created_by_ref=self.identity,
                                source_ref=final_observable["standard_id"],
                                target_ref=host_stix.id,
                            )
                            bundle_objects.append(host_stix)
                            bundle_objects.append(relationship)
                        else:
                            domain = urlparse(address).hostname
                            domain_stix = DomainName(
                                value=domain,
                                object_marking_refs=[stix2.TLP_WHITE],
                                custom_properties={
                                    "labels": [detection_name, "c2 server"],
                                    "created_by_ref": self.identity,
                                },
                            )
                            relationship = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "communicates-with",
                                    final_observable["standard_id"],
                                    domain_stix.id,
                                ),
                                relationship_type="communicates-with",
                                created_by_ref=self.identity,
                                source_ref=final_observable["standard_id"],
                                target_ref=domain_stix.id,
                            )
                            bundle_objects.append(domain_stix)
                            bundle_objects.append(relationship)

        # Attach the domains
        for domain_dict in report.get("network", {}).get("domains", []):
            domain_stix = DomainName(
                value=domain_dict["domain"],
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "created_by_ref": self.identity,
                },
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "communicates-with", final_observable["standard_id"], domain_stix.id
                ),
                relationship_type="communicates-with",
                created_by_ref=self.identity,
                source_ref=final_observable["standard_id"],
                target_ref=domain_stix.id,
            )
            bundle_objects.append(domain_stix)
            bundle_objects.append(relationship)

        # Attach the IP addresses
        for host_dict in report.get("network", {}).get("hosts", []):
            host = host_dict["ip"]
            host_stix = IPv4Address(
                value=host,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={"created_by_ref": self.identity},
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "communicates-with", final_observable["standard_id"], host_stix.id
                ),
                relationship_type="communicates-with",
                created_by_ref=self.identity,
                source_ref=final_observable["standard_id"],
                target_ref=host_stix.id,
            )
            bundle_objects.append(host_stix)
            bundle_objects.append(relationship)

        # Handle CAPE payloads and attach Flare CAPA TTPs if any
        if (
            "CAPE" in report
            and "payloads" in report["CAPE"]
            and report["CAPE"]["payloads"]
        ):
            # Download the zip archive of payloads
            zip_contents = self._get_payloads_zip(task_id)
            zip_obj = io.BytesIO(zip_contents)

            # Extract with "infected" password
            zip_file = pyzipper.AESZipFile(zip_obj)
            zip_file.setpassword(b"infected")

            # Process each payload
            for payload_dict in report["CAPE"]["payloads"]:
                module_path = payload_dict["module_path"]
                sha256 = payload_dict["sha256"]
                cape_type = payload_dict["cape_type"]
                payload_contents = zip_file.read(f"CAPE/{sha256}")
                mime_type = magic.from_buffer(payload_contents, mime=True)

                kwargs = {
                    "file_name": module_path,
                    "data": payload_contents,
                    "mime_type": mime_type,
                    "x_opencti_description": cape_type,
                }
                response = self.helper.api.stix_cyber_observable.upload_artifact(
                    **kwargs
                )
                self.helper.log_info(
                    f'Uploaded CAPE payload with sha256 "{sha256}" and type "{cape_type}".'
                )

                # Create and apply label
                label = self.helper.api.label.create(value=cape_type, color="#ff8178")
                self.helper.api.stix_cyber_observable.add_label(
                    id=response["id"], label_id=label["id"]
                )

                # Create relationship between uploaded payload Artifact and original
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        response["standard_id"],
                        final_observable["standard_id"],
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=response["standard_id"],
                    target_ref=final_observable["standard_id"],
                )
                bundle_objects.append(relationship)

                # Handle Flare CAPA TTPs if any
                if "flare_capa" in payload_dict and payload_dict["flare_capa"]:
                    attck_dict = payload_dict["flare_capa"]["ATTCK"]
                    for tactic in attck_dict:
                        for tp in attck_dict[tactic]:
                            attack_pattern = stix2.AttackPattern(
                                id=AttackPattern.generate_id(tactic, tp),
                                created_by_ref=self.identity,
                                name=tactic,
                                custom_properties={
                                    "x_mitre_id": tp,
                                },
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            relationship = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "uses", response["standard_id"], attack_pattern.id
                                ),
                                relationship_type="uses",
                                created_by_ref=self.identity,
                                source_ref=response["standard_id"],
                                target_ref=attack_pattern.id,
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            bundle_objects.append(attack_pattern)
                            bundle_objects.append(relationship)
                else:
                    self.helper.log_info(
                        f"Could not find flare_capa key or was empty in CAPE payload {sha256}."
                    )

            # Close the zip file
            zip_file.close()

        else:
            self.helper.log_info(
                "Skipping processing CAPE payloads, payloads key is empty or not exists."
            )

        # Serialize and send all bundles
        if bundle_objects:
            bundle = self.helper.stix2_create_bundle(bundle_objects)
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        else:
            return "Nothing to attach"

    def _trigger_sandbox(self, observable):
        self.helper.log_info("Triggering the sandbox...")

        if not observable["importFiles"]:
            raise ValueError(f"No files found for {observable['observable_value']}")

        # Build the URI to download the file
        file_name = observable["importFiles"][0]["name"]
        file_id = observable["importFiles"][0]["id"]
        file_uri = f"{self.octi_api_url}/storage/get/{file_id}"
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)

        # Create file object
        file_obj = io.BytesIO(file_content)

        # Upload file for analysis
        files = {"file": (file_name, file_obj)}

        analysis_options = {
            "options": self.options,
            "route": self.route,
            "priority": self.priority,
            "timeout": self.timeout,
            "enforce_timeout": self.enforce_timeout,
        }

        # Try and extract statically first, if enabled in config
        if self.try_extract:
            analysis_options["static"] = True

        response_dict = self._create_file(
            files=files, analysis_options=analysis_options
        )

        self.helper.log_info(response_dict)

        task_id = response_dict["data"]["task_ids"][0]
        if isinstance(task_id, list):
            task_id = response_dict["data"]["task_ids"][0][0]
        self.helper.log_info(f"Analysis {task_id} has started...")

        # Wait until analysis is finished
        status = None
        while True:
            # Get the task's status
            response_dict = self._get_status(task_id)
            status = response_dict["data"]
            error = response_dict["error"]

            if status == "reported":
                break
            elif error:
                raise ValueError(f'Analysis {task_id} failed with status "{status}".')

            self.helper.log_info(f'Analysis {task_id} has status "{status}"...')
            time.sleep(20)

        # Analysis is finished, process the report
        response_dict = self._get_report(task_id)

        self.helper.log_info(f"Analysis {task_id} finished, processing report...")
        return self._send_knowledge(observable, response_dict)

    def _process_observable(self, observable):
        self.helper.log_info(
            "Processing the observable " + observable["observable_value"]
        )
        # If File or Artifact
        if observable["entity_type"] in ["StixFile", "Artifact"]:
            return self._trigger_sandbox(observable)
        else:
            raise ValueError(
                f"Failed to process observable, {observable['entity_type']} is not a supported entity type."
            )

    def _process_message(self, data: Dict):
        observable = data["enrichment_entity"]

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

    def retry():
        def decorator(func):
            def f2(self, *args, **kwargs):
                attempts = reversed(range(self._max_retries))
                for attempts_remaining in attempts:
                    try:
                        return func(self, *args, **kwargs)
                    except Exception as e:
                        if attempts_remaining > 0:
                            self.helper.log_info(
                                f"Attempts remaining {attempts_remaining}, re-trying after receiving exception: {e}"
                            )
                            time.sleep(self._cooldown_time)
                        else:
                            self.helper.log_info(
                                f"Failed after re-trying {self._max_retries} times with exception: {e}"
                            )
                            raise
                    else:
                        break

            return f2

        return decorator

    # API helper methods with retry wrapping
    @retry()
    def _get_procdump_zip(self, task_id):
        response = requests.get(
            f"{self.cape_api_url}/tasks/get/procdumpfiles/{task_id}/",
            headers=self.headers,
        )
        response.raise_for_status()
        response_contents = response.content
        return response_contents

    @retry()
    def _get_payloads_zip(self, task_id):
        response = requests.get(
            f"{self.cape_api_url}/tasks/get/payloadfiles/{task_id}/",
            headers=self.headers,
        )
        response.raise_for_status()
        response_contents = response.content
        return response_contents

    @retry()
    def _get_report(self, task_id):
        response = requests.get(
            f"{self.cape_api_url}/tasks/get/report/{task_id}/", headers=self.headers
        )
        response.raise_for_status()
        response_dict = response.json()
        return response_dict

    @retry()
    def _get_status(self, task_id):
        response = requests.get(
            f"{self.cape_api_url}/tasks/status/{task_id}/?format=json",
            headers=self.headers,
        )
        response.raise_for_status()
        response_dict = response.json()
        return response_dict

    @retry()
    def _create_file(self, files, analysis_options):
        response = requests.post(
            f"{self.cape_api_url}/tasks/create/file/",
            headers=self.headers,
            files=files,
            data=analysis_options,
        )
        response.raise_for_status()
        response_dict = response.json()
        return response_dict

    def _is_ipv4_address(self, ip):
        m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
        return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        cape_sandbox = CapeSandboxConnector()
        cape_sandbox.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
