# coding: utf-8

import ipaddress
import json
import os
import sys
import time
import stix2
import yaml
from pycti import OpenCTIConnectorHelper, StixCoreRelationship, get_config_variable
from vmray.rest_api import VMRayRESTAPI
from hashlib import sha256
from zipfile import ZipFile
from io import BytesIO
from fnmatch import fnmatch


class VmrayAnalyzerConnector:
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
            type="Organization", name="VMRay", description="VMRay"
        )["standard_id"]

        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )

        # Get Server and API Key from config, use to instantiate the VMRay Rest Client
        server = get_config_variable(
            "VMRAY_ANALYZER_SERVER", ["vmray_analyzer", "server"], config
        )
        api_key = get_config_variable(
            "VMRAY_ANALYZER_API_KEY", ["vmray_analyzer", "api_key"], config
        )
        self.vmray_analyzer_client = VMRayRESTAPI(server=server, api_key=api_key)

        # Get other config values
        self.shareable = get_config_variable(
            "VMRAY_ANALYZER_SHAREABLE", ["vmray_analyzer", "shareable"], config
        )
        self.reanalyze = get_config_variable(
            "VMRAY_ANALYZER_REANALYZE", ["vmray_analyzer", "reanalyze"], config
        )
        default_tlp = get_config_variable(
            "VMRAY_ANALYZER_DEFAULT_TLP", ["vmray_analyzer", "default_tlp"], config
        ).lower()

        if default_tlp == "tlp:clear" or default_tlp == "tlp:white":
            self.default_tlp = stix2.TLP_WHITE
        elif default_tlp == "tlp:green":
            self.default_tlp = stix2.TLP_GREEN
        elif default_tlp == "tlp:amber":
            self.default_tlp = stix2.TLP_AMBER
        elif default_tlp == "tlp:red":
            self.default_tlp = stix2.TLP_RED

        self.max_tlp = get_config_variable(
            "VMRAY_ANALYZER_MAX_TLP", ["vmray_analyzer", "max_tlp"], config
        )
        self.classifications_color = get_config_variable(
            "VMRAY_ANALYZER_CLASSIFICATIONS_COLOR",
            ["vmray_analyzer", "classifications_color"],
            config,
        )
        self.theat_names_color = get_config_variable(
            "VMRAY_ANALYZER_THREAT_NAMES_COLOR",
            ["vmray_analyzer", "threat_names_color"],
            config,
        )
        default_color = get_config_variable(
            "VMRAY_ANALYZER_DEFAULT_COLOR", ["vmray_analyzer", "default_color"], config
        )
        # Create default labels
        self.helper.api.label.create(value="dynamic", color=default_color)
        # Used for passing the external reference to the analysis report around
        self.external_reference = None

    def _process_observable(self, observable):

        # Build params for the submission
        params = {}
        # Must be boolean
        params["shareable"] = (
            self.shareable == True or self.shareable == "true"
        )  # noqa: E712
        params["reanalyze"] = (
            self.reanalyze == True or self.reanalyze == "true"
        )  # noqa: E712

        if observable["entity_type"] == "Artifact":
            # Download the Artifact from OpenCTI
            file_name = observable["importFiles"][0]["name"]
            file_id = observable["importFiles"][0]["id"]
            file_uri = f"{self.octi_api_url}/storage/get/{file_id}"
            file_content = self.helper.api.fetch_opencti_file(file_uri, True)
            file_content_obj = BytesIO(file_content)
            file_content_obj.name = file_name
            file_sha256 = self._get_sha256(file_content)
            params["sample_file"] = file_content_obj
        else:
            raise ValueError(
                f"Failed to process observable, {observable['entity_type']} is not a supported entity type."
            )

        # Store the sample's id and submission id
        submission_id = None
        sample_id = None

        # Check to see if there's an existing submission and reanalyze is False
        if not params["reanalyze"]:
            existing_samples = self.vmray_analyzer_client.call(
                "GET", f"/rest/sample/sha256/{file_sha256}"
            )
            if existing_samples:
                sample_id = existing_samples[0].get("sample_id")
                existing_submissions = self.vmray_analyzer_client.call(
                    "GET", f"/rest/submission/sample/{sample_id}"
                )
                for existing_submission in existing_submissions:
                    # Skip submissions with errors
                    if existing_submission["submission_has_errors"]:
                        continue
                    submission_id = existing_submission.get("submission_id")
                    # Wait for existing submission if not yet finished
                    if not existing_submission["submission_finished"]:
                        self._wait_for_submission(submission_id)

                    break

        # No existing analysis, force re-analysis
        if not sample_id or not submission_id:
            params["reanalyze"] = True
            submit_dict = self.vmray_analyzer_client.call(
                "POST", "/rest/sample/submit", params
            )
            self.helper.log_debug(json.dumps(submit_dict, indent=2))
            submission_id = submit_dict.get("submissions")[0].get("submission_id")
            sample_id = submit_dict["samples"][0]["sample_id"]

            # Wait for the analyses to finish
            self._wait_for_submission(submission_id)

        # Get the sample report
        sample_dict = self.vmray_analyzer_client.call(
            "GET", f"/rest/sample/{sample_id}"
        )
        sample_webif_url = sample_dict["sample_webif_url"]
        sample_classifications = sample_dict["sample_classifications"]
        sample_threat_names = sample_dict["sample_threat_names"]
        sample_score = sample_dict["sample_score"]

        # Attach external reference
        self.external_reference = self.helper.api.external_reference.create(
            source_name="VMRay Analyzer Analysis",
            url=sample_webif_url,
            description="VMRay Analyzer Analysis",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"], external_reference_id=self.external_reference["id"]
        )

        # Attach classification labels
        for classification in sample_classifications:
            label = self.helper.api.label.create(
                value=classification, color=self.classifications_color
            )
            self.helper.api.stix_cyber_observable.add_label(
                id=observable["id"], label_id=label["id"]
            )

        # Attach threat names labels
        for threat_name in sample_threat_names:
            label = self.helper.api.label.create(
                value=threat_name, color=self.theat_names_color
            )
            self.helper.api.stix_cyber_observable.add_label(
                id=observable["id"], label_id=label["id"]
            )

        # Set score of the Artifact
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"],
            input={"key": "x_opencti_score", "value": str(sample_score)},
        )

        # Get the analyses list
        analyses = self.vmray_analyzer_client.call(
            "GET", f"/rest/analysis/submission/{submission_id}"
        )
        analysis_ids = [analysis_dict["analysis_id"] for analysis_dict in analyses]

        # Process analyses list
        return self._process_analyses(observable, analysis_ids)

    def _process_analyses(self, observable, analysis_ids):
        """
        observable: The dict containing the observable to enrich
        analysis_ids: A list containnig analysis ids
        returns: a str representing a message to return to OpenCTI
        """

        bundle_objects = []
        for analysis_id in analysis_ids:
            # Download and process each analysis archive
            self.helper.log_info(
                f"Downloading analysis archive for analysis id: {analysis_id}"
            )
            analysis_archive = self.vmray_analyzer_client.call(
                "GET", f"/rest/analysis/{analysis_id}/archive", raw_data=True
            ).read()
            # Upload the full analysis archive
            self.helper.api.external_reference.add_file(
                id=self.external_reference["id"],
                file_name=f"{analysis_id}_full_analysis.zip",
                data=analysis_archive,
                mime_type="application/zip",
            )
            # Extract the archive
            file_obj = BytesIO(analysis_archive)
            zipfile_obj = ZipFile(file_obj)
            # Handle each file in the archive
            for file_name in zipfile_obj.namelist():
                # Upload the report.pdf
                if file_name == "report/report.pdf":
                    with zipfile_obj.open(file_name) as pdf:
                        self.helper.api.external_reference.add_file(
                            id=self.external_reference["id"],
                            file_name=f"{analysis_id}-report.pdf",
                            data=pdf.read(),
                            mime_type="application/pdf",
                        )
                # Attach any found malware configurations as Note entities
                elif (
                    "malware_configurations/" in file_name
                    and file_name != "malware_configurations/"
                ):
                    with zipfile_obj.open(file_name) as config:
                        config_dict = json.load(config)
                        note = stix2.Note(
                            abstract=f"Malware Configuration ({os.path.basename(file_name)})",
                            content=f"```\n{json.dumps(config_dict, indent=2)}\n```",
                            created_by_ref=self.identity,
                            object_marking_refs=[self.default_tlp],
                            object_refs=[observable["standard_id"]],
                        )
                        bundle_objects.append(note)
                # Upload the behavior json
                elif file_name == "report/behavior.json":
                    with zipfile_obj.open(file_name) as behavior_json:
                        stix_bundle = json.load(behavior_json)
                        self.helper.api.external_reference.add_file(
                            id=self.external_reference["id"],
                            file_name=f"{analysis_id}-{os.path.basename(file_name)}",
                            data=json.dumps(stix_bundle, indent=2),
                            mime_type="application/json",
                        )
                # Handle the stix json files
                elif fnmatch(file_name, "report/artifacts/stix-*.json"):
                    with zipfile_obj.open(file_name) as stix_json:
                        stix_bundle = json.load(stix_json)
                        stix_objects = stix_bundle.get("objects")[0].get("objects")
                        if not stix_objects:
                            self.helper.log_debug(
                                f"Stix bundle {file_name} for analysis {analysis_id} contained no objects"
                            )
                            continue
                        # Upload as external reference file
                        self.helper.api.external_reference.add_file(
                            id=self.external_reference["id"],
                            file_name=f"{analysis_id}-{os.path.basename(file_name)}",
                            data=json.dumps(stix_bundle, indent=2),
                            mime_type="application/json",
                        )
                        # Process the stix json files for domains, ips, and urls
                        # Create relationship between the observable and those entities
                        for key in stix_objects:
                            object_dict = stix_objects[key]
                            object_type = object_dict["type"]
                            object_value = object_dict.get("value")
                            if not object_value:
                                continue
                            if object_type == "url":
                                url_stix = stix2.URL(
                                    value=object_value,
                                    object_marking_refs=[self.default_tlp],
                                    custom_properties={
                                        "labels": ["dynamic"],
                                        "created_by_ref": self.identity,
                                    },
                                )
                                relationship = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "related-to",
                                        observable["standard_id"],
                                        url_stix.id,
                                    ),
                                    relationship_type="related-to",
                                    created_by_ref=self.identity,
                                    source_ref=observable["standard_id"],
                                    target_ref=url_stix.id,
                                    allow_custom=True,
                                )
                                bundle_objects.append(url_stix)
                                bundle_objects.append(relationship)
                            elif object_type == "domain-name":
                                domain_stix = stix2.DomainName(
                                    value=object_value,
                                    object_marking_refs=[self.default_tlp],
                                    custom_properties={
                                        "labels": ["dynamic"],
                                        "created_by_ref": self.identity,
                                    },
                                )
                                relationship = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "communicates-with",
                                        observable["standard_id"],
                                        domain_stix.id,
                                    ),
                                    relationship_type="communicates-with",
                                    created_by_ref=self.identity,
                                    source_ref=observable["standard_id"],
                                    target_ref=domain_stix.id,
                                    allow_custom=True,
                                )
                                bundle_objects.append(domain_stix)
                                bundle_objects.append(relationship)
                            elif object_type == "ipv4-addr":
                                # Exclude private IP addresses
                                if ipaddress.ip_address(object_value).is_private:
                                    self.helper.log_debug(
                                        f"Skipping private IP: {object_value}"
                                    )
                                    continue
                                ipv4_stix = stix2.IPv4Address(
                                    value=object_value,
                                    object_marking_refs=[self.default_tlp],
                                    custom_properties={
                                        "labels": ["dynamic"],
                                        "created_by_ref": self.identity,
                                    },
                                )
                                relationship = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "communicates-with",
                                        observable["standard_id"],
                                        ipv4_stix.id,
                                    ),
                                    relationship_type="communicates-with",
                                    created_by_ref=self.identity,
                                    source_ref=observable["standard_id"],
                                    target_ref=ipv4_stix.id,
                                    allow_custom=True,
                                )
                                bundle_objects.append(ipv4_stix)
                                bundle_objects.append(relationship)

        # Serialize and send bundles
        if bundle_objects:
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        else:
            return "Nothing to attach"

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

    def _wait_for_submission(self, submission_id, sleep_interval=1):
        """
        Wait for an analysis to finish.

        submission_id: an int submission id to wait for
        sleep_interval: seconds to sleep between subsequent requests
        returns: none
        """

        while True:
            submission_data = self.vmray_analyzer_client.call(
                "GET", f"/rest/submission/{submission_id}"
            )

            if submission_data["submission_finished"]:
                self.helper.log_info(f"Submission {submission_id} finished.")
                break
            else:
                self.helper.log_info(
                    f"Submission {submission_id} not yet finished, re-checking in {sleep_interval} seconds."
                )
                time.sleep(sleep_interval)

    def _get_sha256(self, contents):
        """
        Return sha256 of bytes.

        contents: a bytes object to get the sha256 for
        returns: a str of the sha256
        """
        sha256obj = sha256()
        sha256obj.update(contents)
        return sha256obj.hexdigest()

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        vmray_analyzer = VmrayAnalyzerConnector()
        vmray_analyzer.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
