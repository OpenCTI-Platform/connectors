# coding: utf-8

import os
import time

import magic
import stix2
import yaml
from pycti import OpenCTIConnectorHelper, StixCoreRelationship, get_config_variable
from unpac_me_api_client import UnpacMeApi, UnpacMeStatus


class UnpacMeConnector:
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
            name="UnpacMe",
            description="UnpacMe",
        )["standard_id"]

        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )

        # Get URL and private from config, use to instantiate the client
        user_agent = get_config_variable(
            "UNPAC_ME_USER_AGENT",
            ["unpac_me", "user_agent"],
            config,
        )
        api_key = get_config_variable(
            "UNPAC_ME_API_KEY",
            ["unpac_me", "api_key"],
            config,
        )
        self.private = get_config_variable(
            "UNPAC_ME_PRIVATE",
            ["unpac_me", "private"],
            config,
        )
        self.unpacme_client = UnpacMeApi(api_key=api_key, user_agent=user_agent)

        # Other config settings
        self.family_color = get_config_variable(
            "UNPAC_ME_FAMILY_COLOR",
            ["unpac_me", "family_color"],
            config,
        )
        self.default_tag_color = get_config_variable(
            "UNPAC_ME_FAMILY_COLOR",
            ["unpac_me", "tag_color"],
            config,
        )
        self.less_noise = get_config_variable(
            "UNPAC_ME_LESS_NOISE",
            ["unpac_me", "less_noise"],
            config,
        )
        self.max_tlp = get_config_variable(
            "UNPAC_ME_MAX_TLP",
            ["unpac_me", "max_tlp"],
            config,
        )

    def _process_results(self, observable, results):
        bundle_objects = []
        unpack_id = results["id"]

        # Create external reference
        analysis_url = f"https://www.unpac.me/results/{unpack_id}"
        external_reference = self.helper.api.external_reference.create(
            source_name="UnpacMe Results",
            url=analysis_url,
            description="UnpacMe Results",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"],
            external_reference_id=external_reference["id"],
        )

        # Create default labels
        extracted_label = self.helper.api.label.create(
            value="extracted", color=self.default_tag_color
        )

        # Parse the results
        label_ids = []
        for result_dict in results["results"]:
            sha256 = result_dict["hashes"]["sha256"]

            # If less noise, check to ensure the files were identified as malware
            if self.less_noise:
                self.helper.log_info("Less noise is enabled.")
                if not result_dict["malware_id"]:
                    self.helper.log_info(
                        f"Skipping upload of {sha256} as it had no matching family."
                    )
                    continue

            # Download the file
            file_contents = self.unpacme_client.download(sha256=sha256)

            # Upload as Artifact to OpenCTI
            mime_type = magic.from_buffer(file_contents, mime=True)

            kwargs = {
                "file_name": sha256,
                "data": file_contents,
                "mime_type": mime_type,
                "x_opencti_description": "UnpacMe extracted file.",
            }
            response = self.helper.api.stix_cyber_observable.upload_artifact(**kwargs)

            # Create Relationship between original and newly uploaded Artifact
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", response["standard_id"], observable["standard_id"]
                ),
                relationship_type="related-to",
                created_by_ref=self.identity,
                source_ref=response["standard_id"],
                target_ref=observable["standard_id"],
            )
            bundle_objects.append(relationship)

            # Attach default "extracted" label
            if response["id"] != observable["id"]:
                self.helper.api.stix_cyber_observable.add_label(
                    id=response["id"], label_id=extracted_label["id"]
                )

            # If found malware ids, attach as labels
            for malware_id_dict in result_dict["malware_id"]:
                family_label = self.helper.api.label.create(
                    value=malware_id_dict["name"], color=self.family_color
                )
                self.helper.api.stix_cyber_observable.add_label(
                    id=response["id"], label_id=family_label["id"]
                )
                label_ids.append(family_label["id"])

        # Attach all identified tags to the Artifact
        for label_id in label_ids:
            self.helper.api.stix_cyber_observable.add_label(
                id=observable["id"], label_id=family_label["id"]
            )

        # Serialize and send all bundles
        if bundle_objects:
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        else:
            return "Nothing to attach"

    def _process_file(self, observable):

        if not observable["importFiles"]:
            raise ValueError(f"No files found for {observable['observable_value']}")

        # Build the URI to download the file
        file_id = observable["importFiles"][0]["id"]
        file_uri = f"{self.octi_api_url}/storage/get/{file_id}"
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)

        # Submit sample for analysis
        upload = self.unpacme_client.upload(data=file_content, private=self.private)

        # Wait for the analysis to finish
        while True:

            response = self.unpacme_client.status(upload=upload)

            if response == UnpacMeStatus.COMPLETE:
                break
            elif response == UnpacMeStatus.FAIL:
                raise ValueError(f"UnpacMe failed to analyze {file_id}")

            time.sleep(20)

        # Analysis is complete, get the results
        results = self.unpacme_client.results(upload=upload)
        results = results.raw_json

        self.helper.log_info(f"Analysis complete, processing results: {results}...")

        return self._process_results(observable, results)

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

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        unpac_me = UnpacMeConnector()
        unpac_me.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
