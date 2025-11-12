# coding: utf-8

import os
import sys
import time
from typing import Dict

import yaml
from intezer_api import IntezerApi
from pycti import OpenCTIConnectorHelper, get_config_variable


class IntezerSandboxConnector:
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
            name="Intezer Sandbox",
            description="Intezer Sandbox",
        )["standard_id"]

        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )

        # Get api key from config, use to instantiate the client
        api_key = get_config_variable(
            "INTEZER_SANDBOX_API_KEY",
            ["intezer_sandbox", "api_key"],
            config,
        )
        self.intezer_client = IntezerApi(api_key=api_key)

        # Other config settings
        self.family_color = get_config_variable(
            "INTEZER_SANDBOX_FAMILY_COLOR",
            ["intezer_sandbox", "family_color"],
            config,
        )
        self.malicious_color = get_config_variable(
            "INTEZER_SANDBOX_MALICIOUS_COLOR",
            ["intezer_sandbox", "malicious_color"],
            config,
        )
        self.trusted_color = get_config_variable(
            "INTEZER_SANDBOX_TRUSTED_COLOR",
            ["intezer_sandbox", "trusted_color"],
            config,
        )
        self.unknown_color = get_config_variable(
            "INTEZER_SANDBOX_UNKNOWN_COLOR",
            ["intezer_sandbox", "unknown_color"],
            config,
        )
        self.suspicious_color = get_config_variable(
            "INTEZER_SANDBOX_SUSPICIOUS_COLOR",
            ["intezer_sandbox", "suspicious_color"],
            config,
        )
        self.max_tlp = get_config_variable(
            "INTEZER_SANDBOX_MAX_TLP",
            ["intezer_sandbox", "max_tlp"],
            config,
        )

    def _process_report(self, observable, report):
        self.helper.log_info(report)

        # Create external reference
        analysis_url = report["result"]["analysis_url"]
        external_reference = self.helper.api.external_reference.create(
            source_name="Intezer Sandbox Results",
            url=analysis_url,
            description="Intezer Sandbox Results",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"],
            external_reference_id=external_reference["id"],
        )

        # Attach family name as label if present
        if "family_name" in report["result"] and report["result"]["family_name"]:
            family_label = self.helper.api.label.create(
                value=report["result"]["family_name"], color=self.family_color
            )
            self.helper.api.stix_cyber_observable.add_label(
                id=observable["id"], label_id=family_label["id"]
            )

        # Attach verdict as label with color
        color = self.malicious_color
        verdict = report["result"]["verdict"]
        if verdict == "suspicious":
            color = self.suspicious_color
        elif verdict == "unknown":
            color = self.unknown_color
        elif verdict == "trusted":
            color = self.trusted_color

        verdict_label = self.helper.api.label.create(value=verdict, color=color)
        self.helper.api.stix_cyber_observable.add_label(
            id=observable["id"], label_id=verdict_label["id"]
        )

        return "Nothing to attach"

    def _process_file(self, observable):
        if not observable["importFiles"]:
            raise ValueError(f"No files found for {observable['observable_value']}")

        # Build the URI to download the file
        file_name = observable["importFiles"][0]["name"]
        file_id = observable["importFiles"][0]["id"]
        file_uri = f"{self.octi_api_url}/storage/get/{file_id}"
        file_contents = self.helper.api.fetch_opencti_file(file_uri, True)

        # Submit sample for analysis
        result_url = self.intezer_client.upload_file(
            file_name=file_name, file_contents=file_contents
        )

        # Wait for the analysis to finish
        status = None
        report = None
        while True:
            report = self.intezer_client.get_analysis_report(result_url)
            status = report["status"]

            if status == "succeeded":
                break
            elif status == "error" or status == "failed" or status == "expired":
                raise ValueError(
                    f"Intezer Sandbox failed to analyze {file_name}, status: {status}."
                )

            self.helper.log_info(f"Analysis for {file_name} has status {status}...")
            time.sleep(20)

        self.helper.log_info("Analysis succeeded, processing results...")

        return self._process_report(observable, report)

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

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        intezer_sandbox = IntezerSandboxConnector()
        intezer_sandbox.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
