# coding: utf-8

import os
import yaml
import time
import io
import json
import re
import magic
import ipaddress
from triage import Client
from hashlib import sha256

from stix2 import (
    Bundle,
    AttackPattern,
    Relationship,
    TLP_WHITE,
    Note,
)
from pycti import (
    OpenCTIConnectorHelper,
    OpenCTIStix2Utils,
    get_config_variable,
    SimpleObservable,
)


class HatchingTriageSandboxConnector:
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
            name="Hatching Triage",
            description="Hatching Triage",
        )["standard_id"]

        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )

        # Get URL and token from config, use to instantiate the Triage Client
        base_url = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_BASE_URL",
            ["hatching_triage_sandbox", "base_url"],
            config,
        )
        token = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_TOKEN",
            ["hatching_triage_sandbox", "token"],
            config,
        )
        self.triage_client = Client(token, root_url=base_url)

        # Get other config values
        self.use_existing_analysis = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_USE_EXISTING_ANALYSIS",
            ["hatching_triage_sandbox", "use_existing_analysis"],
            config,
        )
        self.family_color = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_FAMILY_COLOR",
            ["hatching_triage_sandbox", "family_color"],
            config,
        )
        self.botnet_color = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_BOTNET_COLOR",
            ["hatching_triage_sandbox", "botnet_color"],
            config,
        )
        self.campaign_color = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_CAMPAIGN_COLOR",
            ["hatching_triage_sandbox", "campaign_color"],
            config,
        )
        self.default_tag_color = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_TAG_COLOR",
            ["hatching_triage_sandbox", "tag_color"],
            config,
        )
        self.max_tlp = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_MAX_TLP",
            ["hatching_triage_sandbox", "max_tlp"],
            config,
        )

    def _process_overview_report(self, observable, overview_dict, sample_id):
        bundle_objects = []

        # Create external reference
        # Analysis URL
        external_reference = self.helper.api.external_reference.create(
            source_name="Hatching Triage Sandbox Analysis",
            url=f"https://tria.ge/{sample_id}/",
            description="Hatching Triage Sandbox Analysis",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"],
            external_reference_id=external_reference["id"],
        )

        # Create labels from the tags
        if "tags" in overview_dict["analysis"]:
            for tag in overview_dict["analysis"]["tags"]:

                # Set the label color depending on tag type
                # Note: Only certain tags are separated by a colon
                # Those are the tags we are colorizing
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

                # Create and add the label
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
                    self.helper.api.log_info("rule key not found, skipping...")
                    continue

                # Create a Note
                config_json = json.dumps(extracted_dict, indent=2)
                config_rule = extracted_dict["config"]["rule"]
                note = Note(
                    abstract=f"{config_rule} Config",
                    content=f"```\n{config_json}\n```",
                    created_by_ref=self.identity,
                    object_refs=[observable["standard_id"]],
                )
                bundle_objects.append(note)

                # Create Observables and Relationships for C2s
                c2_list = extracted_dict.get("config").get("c2", [])
                for c2 in c2_list:
                    # Differentiate between C2 IP and URL
                    parsed = c2.split(":")[0]
                    key = "Url"
                    relationship_type = "communicates-with"
                    if self._is_ipv4_address(parsed):
                        key = "IPv4-Addr"
                    else:
                        parsed = c2
                        relationship_type = "related-to"
                    host_stix = SimpleObservable(
                        id=OpenCTIStix2Utils.generate_random_stix_id(
                            "x-opencti-simple-observable"
                        ),
                        labels=[config_rule, "c2 server"],
                        key=f"{key}.value",
                        value=parsed,
                        created_by_ref=self.identity,
                    )
                    relationship = Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type=relationship_type,
                        created_by_ref=self.identity,
                        source_ref=observable["standard_id"],
                        target_ref=host_stix.id,
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
                        host_stix = SimpleObservable(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "x-opencti-simple-observable"
                            ),
                            labels=[config_rule, "credentials"],
                            key="X-OpenCTI-Hostname.value",
                            value=host,
                            created_by_ref=self.identity,
                        )

                        relationship = Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="related-to",
                            created_by_ref=self.identity,
                            source_ref=observable["standard_id"],
                            target_ref=host_stix.id,
                        )

                        bundle_objects.append(host_stix)
                        bundle_objects.append(relationship)

                    if protocol == "smtp":
                        # Add Email Address Observable
                        host_stix = SimpleObservable(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "x-opencti-simple-observable"
                            ),
                            labels=[config_rule, "credentials"],
                            key="Email-Addr.value",
                            value=username,
                            created_by_ref=self.identity,
                        )

                        relationship = Relationship(
                            id=OpenCTIStix2Utils.generate_random_stix_id(
                                "relationship"
                            ),
                            relationship_type="related-to",
                            created_by_ref=self.identity,
                            source_ref=observable["standard_id"],
                            target_ref=host_stix.id,
                        )

                        bundle_objects.append(host_stix)
                        bundle_objects.append(relationship)

                # Download task file, wait for it to become available
                # Give up after 5 tries
                task_id = extracted_dict["tasks"][0]
                filename = extracted_dict["dumped_file"]
                file_contents = self.triage_client.sample_task_file(
                    sample_id, task_id, filename
                )

                for x in range(5):
                    # Sample not yet available, sleep
                    if b"NOT_AVAILABLE" in file_contents[:30]:
                        time.sleep(10)
                        continue

                    file_contents = self.triage_client.sample_task_file(
                        sample_id, task_id, filename
                    )

                if b"NOT_AVAILABLE" in file_contents[:30]:
                    self.helper.api.log_info(
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
                relationship = Relationship(
                    id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                    relationship_type="related-to",
                    created_by_ref=self.identity,
                    source_ref=response["standard_id"],
                    target_ref=observable["standard_id"],
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

                # Create Url Observables and Relationships
                dropper_urls = dropper_dict["urls"]
                for url_dict in dropper_urls:
                    dropper_type = url_dict["type"]
                    url = url_dict["url"]
                    url_stix = SimpleObservable(
                        id=OpenCTIStix2Utils.generate_random_stix_id(
                            "x-opencti-simple-observable"
                        ),
                        labels=[dropper_type],
                        key="Url.value",
                        value=url,
                        created_by_ref=self.identity,
                        object_marking_refs=[TLP_WHITE],
                    )
                    relationship = Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="related-to",
                        created_by_ref=self.identity,
                        source_ref=observable["standard_id"],
                        target_ref=url_stix.id,
                    )
                    bundle_objects.append(url_stix)
                    bundle_objects.append(relationship)

                    # Create dropper type label
                    self.helper.api.label.create(
                        value=dropper_type, color=self.default_tag_color
                    )

        # Attach domains
        domains = [
            task_dict.get("iocs", {}).get("domains", [])
            for task_dict in overview_dict["targets"]
        ]
        for domain in domains[0]:
            domain_stix = SimpleObservable(
                id=OpenCTIStix2Utils.generate_random_stix_id(
                    "x-opencti-simple-observable"
                ),
                labels=["dynamic"],
                key="Domain-Name.value",
                value=domain,
                created_by_ref=self.identity,
                object_marking_refs=[TLP_WHITE],
            )
            relationship = Relationship(
                id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                relationship_type="communicates-with",
                created_by_ref=self.identity,
                source_ref=observable["standard_id"],
                target_ref=domain_stix.id,
            )
            bundle_objects.append(domain_stix)
            bundle_objects.append(relationship)

        # Attach IP addresses
        ips = [
            task_dict.get("iocs", {}).get("ips", [])
            for task_dict in overview_dict["targets"]
        ]
        for ip in ips[0]:

            # Filter out non-global and known DNS IPs
            if not ipaddress.ip_address(ip).is_global:
                continue
            if ip in ["8.8.8.8", "8.8.4.4"]:
                continue

            host_stix = SimpleObservable(
                id=OpenCTIStix2Utils.generate_random_stix_id(
                    "x-opencti-simple-observable"
                ),
                labels=["dynamic"],
                key="IPv4-Addr.value",
                value=ip,
                created_by_ref=self.identity,
            )
            relationship = Relationship(
                id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                relationship_type="communicates-with",
                created_by_ref=self.identity,
                source_ref=observable["standard_id"],
                target_ref=host_stix.id,
            )
            bundle_objects.append(host_stix)
            bundle_objects.append(relationship)

        # Attach the TTPs
        if "signatures" in overview_dict:
            for signature_dict in overview_dict["signatures"]:

                # Skip any dicts without a ttps key
                if "ttp" not in signature_dict:
                    continue

                name = signature_dict["name"]
                ttps = signature_dict["ttp"]

                for ttp in ttps:

                    attack_pattern = AttackPattern(
                        id=OpenCTIStix2Utils.generate_random_stix_id("attack-pattern"),
                        created_by_ref=self.identity,
                        name=name,
                        custom_properties={
                            "x_mitre_id": ttp,
                        },
                        object_marking_refs=[TLP_WHITE],
                    )

                    relationship = Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="uses",
                        created_by_ref=self.identity,
                        source_ref=observable["standard_id"],
                        target_ref=attack_pattern.id,
                        object_marking_refs=[TLP_WHITE],
                    )
                    bundle_objects.append(attack_pattern)
                    bundle_objects.append(relationship)

        # Serialize and send all bundles
        if bundle_objects:
            bundle = Bundle(objects=bundle_objects).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        else:
            return "Nothing to attach"

    def _process_file(self, observable):
        self.helper.log_info("Triggering the sandbox...")

        if not observable["importFiles"]:
            raise ValueError(f"No files found for {observable['observable_value']}")

        # Build the URI to download the file
        file_name = observable["importFiles"][0]["name"]
        file_id = observable["importFiles"][0]["id"]
        file_uri = f"{self.octi_api_url}/storage/get/{file_id}"
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)
        sha256 = self._get_sha256(file_content)
        sample_id = None

        if self.use_existing_analysis:
            # Perform a search of the sha256 to see if there's any existing analyses
            search_paginator = self.triage_client.search(f"sha256:{sha256}", max=1)
            for search in search_paginator:
                existing_status = search["status"]
                if existing_status == "reported":
                    sample_id = search["id"]
                    self.helper.log_info(
                        f"Found existing analysis with id {sample_id} and status {existing_status}."
                    )
                elif existing_status == "pending":
                    sample_id = search["id"]
                    self.helper.log_info(
                        f"Found existing analysis with id {sample_id} and status {existing_status}."
                    )
                    self._wait_for_analysis(sample_id)
                # Don't paginate, just get the first result
                break

        if sample_id is None:
            file_obj = io.BytesIO(file_content)
            sample_json = self.triage_client.submit_sample_file(file_name, file_obj)
            sample_id = sample_json["id"]
            sample_status = sample_json["status"]
            self.helper.log_info(
                f'Started new analysis {sample_id}, has status "{sample_status}".'
            )
            self._wait_for_analysis(sample_id)

        # Get the Overview report
        overview_dict = self.triage_client.overview_report(sample_id)

        return self._process_overview_report(observable, overview_dict, sample_id)

    def _process_observable(self, observable):
        self.helper.log_info(
            "Processing the observable " + observable["observable_value"]
        )

        # If File, Artifact
        if observable["entity_type"] == "Artifact":
            return self._process_file(observable)
        else:
            raise ValueError(
                f"Failed to process observable, {observable['entity_type']} is not a supported entity type."
            )

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

    def _wait_for_analysis(self, sample_id):
        """
        Wait for an analysis to finish.

        sample_id: a str representing the sample id
        returns: none
        """

        for events in self.triage_client.sample_events(sample_id):
            if events["status"] == "pending":
                self.helper.log_info(
                    f"Analysis {sample_id} has status \"{events['status']}\"."
                )
            elif events["status"] == "reported":
                self.helper.log_info(f"Analysis {sample_id} has finished.")
                break
            elif events["status"] == "failed":
                raise ValueError(f"Analysis {sample_id} failed.")

    def _get_sha256(self, contents):
        """
        Return sha256 of bytes.

        contents: a bytes object to get the sha256 for
        returns: a str of the sha256
        """
        sha256obj = sha256()
        sha256obj.update(contents)
        return sha256obj.hexdigest()

    def _is_ipv4_address(self, ip):
        m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
        return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        hatching_triage_sandbox = HatchingTriageSandboxConnector()
        hatching_triage_sandbox.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
