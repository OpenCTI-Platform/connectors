import io
import ipaddress
import json
import re
import time
from hashlib import sha256
from typing import Dict

import magic
import pycti
import stix2
from connector.settings import ConnectorSettings
from pycti import (
    AttackPattern,
    CustomObservableHostname,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from stix2 import URL, DomainName, EmailAddress, IPv4Address
from triage import Client


class HatchingTriageSandboxConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Hatching Triage",
            description="Hatching Triage",
        )["standard_id"]

        self.octi_api_url = str(self.config.opencti.url).rstrip("/")

        # Instantiate the Triage Client
        self.base_url = self.config.hatching_triage_sandbox.base_url
        token = self.config.hatching_triage_sandbox.token.get_secret_value()
        self.triage_client = Client(token, root_url=self.base_url)

        # Get other config values
        self.use_existing_analysis = (
            self.config.hatching_triage_sandbox.use_existing_analysis
        )
        self.family_color = self.config.hatching_triage_sandbox.family_color
        self.botnet_color = self.config.hatching_triage_sandbox.botnet_color
        self.campaign_color = self.config.hatching_triage_sandbox.campaign_color
        self.default_tag_color = self.config.hatching_triage_sandbox.tag_color
        self.max_tlp = self.config.hatching_triage_sandbox.max_tlp

    def _process_overview_report(
        self, observable, overview_dict, sample_id, entity_type
    ):
        bundle_objects = []

        if "us-sandbox.recordedfuture.com" in self.base_url:
            report_url = f"https://us-sandbox.recordedfuture.com/{sample_id}/"
        elif "sandbox.recordedfuture.com" in self.base_url:
            report_url = f"https://sandbox.recordedfuture.com/{sample_id}/"
        else:
            report_url = f"https://triage.ge/{sample_id}/"

        # Create external reference
        external_reference = self.helper.api.external_reference.create(
            source_name="Hatching Triage Sandbox Analysis",
            url=report_url,
            description="Hatching Triage Sandbox Analysis",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"],
            external_reference_id=external_reference["id"],
        )

        # Create labels from the tags
        if "tags" in overview_dict["analysis"]:
            for tag in overview_dict["analysis"]["tags"]:
                tag_split = tag.split(":")
                tag_value = tag
                label_color = self.default_tag_color
                if len(tag_split) == 2:
                    if "family" == tag_split[0]:
                        label_color = self.family_color
                    elif "botnet" == tag_split[0]:
                        label_color = self.botnet_color
                    elif "campaign" == tag_split[0]:
                        label_color = self.campaign_color
                    tag_value = tag_split[1]

                label = self.helper.api.label.create(value=tag_value, color=label_color)
                self.helper.api.stix_cyber_observable.add_label(
                    id=observable["id"], label_id=label["id"]
                )

        # Create default labels
        self.helper.api.label.create(value="c2 server", color=self.default_tag_color)
        self.helper.api.label.create(value="credentials", color=self.default_tag_color)
        self.helper.api.label.create(value="dynamic", color=self.default_tag_color)
        extracted_label = self.helper.api.label.create(
            value="extracted", color=self.default_tag_color
        )
        self.helper.api.label.create(value="dropper", color=self.default_tag_color)

        # Process extracted key
        extracted_list = overview_dict.get("extracted", [])
        for extracted_dict in extracted_list:
            # Handle config
            if "config" in extracted_dict:
                if "rule" not in extracted_dict["config"]:
                    self.helper.connector_logger.info("rule key not found, skipping...")
                    continue
                # Create a Note
                config_json = json.dumps(extracted_dict, indent=2)
                config_rule = extracted_dict["config"]["rule"]
                note_content = f"```\n{config_json}\n```"
                note = stix2.Note(
                    id=pycti.Note.generate_id(None, note_content),
                    abstract=f"{config_rule} Config",
                    content=note_content,
                    created_by_ref=self.identity,
                    object_refs=[observable["standard_id"]],
                )
                bundle_objects.append(note)
                # Create Observables and Relationships for C2s
                c2_list = extracted_dict.get("config").get("c2", [])
                for c2 in c2_list:
                    parsed = c2.split(":")[0]
                    key = "Url"
                    relationship_type = (
                        "communicates-with"
                        if entity_type == "artifact"
                        else "related-to"
                    )
                    if self._is_ipv4_address(parsed):
                        key = "IPv4-Addr"
                    else:
                        parsed = c2
                        relationship_type = "related-to"
                    host_stix = None
                    if key == "Url":
                        host_stix = URL(
                            value=parsed,
                            custom_properties={
                                "labels": [config_rule, "c2 server"],
                                "created_by_ref": self.identity,
                            },
                        )
                    elif key == "IPv4-Addr":
                        host_stix = IPv4Address(
                            value=parsed,
                            custom_properties={
                                "labels": [config_rule, "c2 server"],
                                "created_by_ref": self.identity,
                            },
                        )
                    if host_stix is not None:
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                relationship_type,
                                observable["standard_id"],
                                host_stix.id,
                            ),
                            relationship_type=relationship_type,
                            created_by_ref=self.identity,
                            source_ref=observable["standard_id"],
                            target_ref=host_stix.id,
                            allow_custom=True,
                        )
                        bundle_objects.append(host_stix)
                        bundle_objects.append(relationship)
                # Create Observables and Relationships for credentials
                creds_list = extracted_dict.get("config").get("credentials", [])
                for cred_dict in creds_list:
                    host = cred_dict.get("host", None)
                    username = cred_dict.get("username")
                    protocol = cred_dict.get("protocol")
                    if host:
                        host_stix = CustomObservableHostname(
                            value=host,
                            custom_properties={
                                "labels": [config_rule, "credentials"],
                                "created_by_ref": self.identity,
                            },
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                observable["standard_id"],
                                host_stix.id,
                            ),
                            relationship_type="related-to",
                            created_by_ref=self.identity,
                            source_ref=observable["standard_id"],
                            target_ref=host_stix.id,
                            allow_custom=True,
                        )
                        bundle_objects.append(host_stix)
                        bundle_objects.append(relationship)
                    if protocol == "smtp" and username:
                        email_stix = EmailAddress(
                            value=username,
                            custom_properties={
                                "labels": [config_rule, "credentials"],
                                "created_by_ref": self.identity,
                            },
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                observable["standard_id"],
                                email_stix.id,
                            ),
                            relationship_type="related-to",
                            created_by_ref=self.identity,
                            source_ref=observable["standard_id"],
                            target_ref=email_stix.id,
                            allow_custom=True,
                        )
                        bundle_objects.append(email_stix)
                        bundle_objects.append(relationship)
                # Download task file, wait for it to become available
                task_id = extracted_dict["tasks"][0]
                filename = extracted_dict["dumped_file"]
                file_contents = self.triage_client.sample_task_file(
                    sample_id, task_id, filename
                )
                for x in range(5):
                    if b"NOT_AVAILABLE" in file_contents[:30]:
                        time.sleep(10)
                        continue
                    file_contents = self.triage_client.sample_task_file(
                        sample_id, task_id, filename
                    )

                if b"NOT_AVAILABLE" in file_contents[:30]:
                    self.helper.connector_logger.info(
                        "Maximum attempts tried to obtain extracted file, skipping..."
                    )
                    continue
                # Upload task file to OpenCTI
                mime_type = magic.from_buffer(file_contents, mime=True)
                kwargs = {
                    "file_name": f"{sample_id}_{filename}",
                    "data": file_contents,
                    "mime_type": mime_type,
                    "x_opencti_description": f"Extracted file from sample ID {sample_id} and task ID {task_id}.",
                }
                response = self.helper.api.stix_cyber_observable.upload_artifact(
                    **kwargs
                )
                # Create Relationship between original Observable and the extracted
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        response["standard_id"],
                        observable["standard_id"],
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=response["standard_id"],
                    target_ref=observable["standard_id"],
                    allow_custom=True,
                )
                bundle_objects.append(relationship)

                # Create and apply labels to extracted file
                label = self.helper.api.label.create(
                    value=config_rule, color=self.family_color
                )
                self.helper.api.stix_cyber_observable.add_label(
                    id=response["id"], label_id=label["id"]
                )
                self.helper.api.stix_cyber_observable.add_label(
                    id=response["id"], label_id=extracted_label["id"]
                )
            # Handle dropper
            if "dropper" in extracted_dict:
                dropper_dict = extracted_dict["dropper"]
                dropper_urls = dropper_dict["urls"]
                for url_dict in dropper_urls:
                    dropper_type = url_dict["type"]
                    url = url_dict["url"]
                    url_stix = URL(
                        value=url.rstrip(),
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "labels": [dropper_type],
                            "created_by_ref": self.identity,
                        },
                    )
                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", observable["standard_id"], url_stix.id
                        ),
                        relationship_type="related-to",
                        created_by_ref=self.identity,
                        source_ref=observable["standard_id"],
                        target_ref=url_stix.id,
                        allow_custom=True,
                    )
                    bundle_objects.append(url_stix)
                    bundle_objects.append(relationship)
                    self.helper.api.label.create(
                        value=dropper_type, color=self.default_tag_color
                    )

        # Attach domains
        if overview_dict.get("targets"):
            relationship_type = (
                "communicates-with" if entity_type == "artifact" else "related-to"
            )

            domains = [
                task_dict.get("iocs", {}).get("domains", [])
                for task_dict in overview_dict["targets"]
            ]
            for domain in domains[0]:
                domain_stix = DomainName(
                    value=domain,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "labels": ["dynamic"],
                        "created_by_ref": self.identity,
                    },
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        relationship_type, observable["standard_id"], domain_stix.id
                    ),
                    relationship_type=relationship_type,
                    created_by_ref=self.identity,
                    source_ref=observable["standard_id"],
                    target_ref=domain_stix.id,
                    allow_custom=True,
                )
                bundle_objects.append(domain_stix)
                bundle_objects.append(relationship)
            # Attach IP addresses
            ips = [
                task_dict.get("iocs", {}).get("ips", [])
                for task_dict in overview_dict["targets"]
            ]
            for ip in ips[0]:
                if not ipaddress.ip_address(ip).is_global:
                    continue
                if ip in ["8.8.8.8", "8.8.4.4"]:
                    continue
                host_stix = IPv4Address(
                    value=ip,
                    custom_properties={
                        "labels": ["dynamic"],
                        "created_by_ref": self.identity,
                    },
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        relationship_type, observable["standard_id"], host_stix.id
                    ),
                    relationship_type=relationship_type,
                    created_by_ref=self.identity,
                    source_ref=observable["standard_id"],
                    target_ref=host_stix.id,
                    allow_custom=True,
                )
                bundle_objects.append(host_stix)
                bundle_objects.append(relationship)

        # Attach the TTPs
        if "signatures" in overview_dict:
            for signature_dict in overview_dict["signatures"]:
                if "ttp" not in signature_dict:
                    continue
                name = signature_dict["name"]
                ttps = signature_dict["ttp"]
                for ttp in ttps:
                    attack_pattern = stix2.AttackPattern(
                        id=AttackPattern.generate_id(name, ttp),
                        created_by_ref=self.identity,
                        name=name,
                        custom_properties={
                            "x_mitre_id": ttp,
                        },
                        object_marking_refs=[stix2.TLP_WHITE],
                        allow_custom=True,
                    )

                    relationship_type = (
                        "uses" if entity_type == "artifact" else "related-to"
                    )

                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            relationship_type,
                            observable["standard_id"],
                            attack_pattern.id,
                        ),
                        relationship_type="uses",
                        created_by_ref=self.identity,
                        source_ref=observable["standard_id"],
                        target_ref=attack_pattern.id,
                        object_marking_refs=[stix2.TLP_WHITE],
                        allow_custom=True,
                    )
                    bundle_objects.append(attack_pattern)
                    bundle_objects.append(relationship)

        # Serialize and send all bundles
        if bundle_objects:
            return self._send_bundle(bundle_objects)
        else:
            return "Nothing to attach"

    def _send_bundle(self, bundle_objects):
        bundle = self.helper.stix2_create_bundle(bundle_objects)
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"

    def _process_file(self, observable, entity_type):
        self.helper.connector_logger.info("Triggering the sandbox...")

        sample_id = None
        observable_value = observable["observable_value"]

        if entity_type == "artifact":
            if not observable["importFiles"]:
                raise ValueError(f"No files found for {observable_value}")

            file_name = observable["importFiles"][0]["name"]
            file_id = observable["importFiles"][0]["id"]
            file_uri = f"{self.octi_api_url}/storage/get/{file_id}"
            file_content = self.helper.api.fetch_opencti_file(file_uri, True)
            sha256_hash = self._get_sha256(file_content)

            search_query = f"sha256:{sha256_hash}"
            sample_id = self._search_for_analysis(search_query)

            if sample_id is None:
                sample_id = self._submit_sample(
                    file_name=file_name, file_content=file_content
                )

        if entity_type == "url":
            search_query = f"url:{observable_value}"
            sample_id = self._search_for_analysis(search_query)

            if sample_id is None:
                sample_id = self._submit_sample(url=observable_value)

        # Get the Overview report
        overview_dict = self.triage_client.overview_report(sample_id)

        return self._process_overview_report(
            observable, overview_dict, sample_id, entity_type
        )

    def _search_for_analysis(self, search_query):
        sample_id = None

        if self.use_existing_analysis:
            search_paginator = self.triage_client.search(query=search_query, max=1)
            for search in search_paginator:
                existing_status = search["status"]
                if existing_status == "reported":
                    sample_id = search["id"]
                    self.helper.connector_logger.info(
                        f"Found existing analysis with id {sample_id} and status {existing_status}."
                    )
                elif existing_status == "pending":
                    sample_id = search["id"]
                    self.helper.connector_logger.info(
                        f"Found existing analysis with id {sample_id} and status {existing_status}."
                    )
                    self._wait_for_analysis(sample_id)
                break

        return sample_id

    def _submit_sample(self, url=None, file_name=None, file_content=None):
        sample_json = None

        if file_content is not None:
            file_obj = io.BytesIO(file_content)
            sample_json = self.triage_client.submit_sample_file(
                filename=file_name, file=file_obj
            )
        elif url is not None:
            sample_json = self.triage_client.submit_sample_url(url=url)

        sample_id = sample_json["id"]
        sample_status = sample_json["status"]
        self.helper.connector_logger.info(
            f'Started new analysis {sample_id}, has status "{sample_status}".'
        )
        self._wait_for_analysis(sample_id)

        return sample_id

    def _process_observable(self, observable, entity_type):
        self.helper.connector_logger.info(
            "Processing the observable " + observable["observable_value"]
        )
        return self._process_file(observable, entity_type)

    def _process_message(self, data: Dict):
        observable = data["enrichment_entity"]
        stix_objects = data["stix_objects"]
        entity_type = observable["entity_type"].lower()

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        if entity_type in ["artifact", "url"]:
            return self._process_observable(observable, entity_type)
        else:
            if not data.get("event_type"):
                self._send_bundle(stix_objects)
            else:
                raise ValueError(
                    f"Failed to process observable, {observable['entity_type']} is not a supported entity type."
                )

    def _wait_for_analysis(self, sample_id):
        """Wait for an analysis to finish."""
        for events in self.triage_client.sample_events(sample_id):
            if events["status"] == "pending":
                self.helper.connector_logger.info(
                    f"Analysis {sample_id} has status \"{events['status']}\"."
                )
            elif events["status"] == "reported":
                self.helper.connector_logger.info(f"Analysis {sample_id} has finished.")
                break
            elif events["status"] == "failed":
                raise ValueError(f"Analysis {sample_id} failed.")

    def _get_sha256(self, contents):
        """Return sha256 of bytes."""
        sha256obj = sha256()
        sha256obj.update(contents)
        return sha256obj.hexdigest()

    def _is_ipv4_address(self, ip):
        m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
        return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))

    def run(self) -> None:
        self.helper.listen(message_callback=self._process_message)
