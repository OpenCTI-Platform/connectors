# coding: utf-8

import os
import yaml
import time
import io
import magic
import vt

from stix2 import Bundle, Relationship

from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils, get_config_variable


class VirustotalDownloaderConnector:
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
            type="Organization", name="Virustotal", description="Virustotal"
        )["standard_id"]

        # Get other config values
        api_key = get_config_variable(
            "VIRUSTOTAL_DOWNLOADER_API_KEY",
            ["virustotal_downloader", "api_key"],
            config,
        )
        self.api_client = vt.Client(api_key)

    def _process_hash(self, observable):

        hash_value = observable["observable_value"]
        artifact_id = None
        bundle_objects = []

        try:

            # Attempt to source the file contents from the hash
            bytes_obj = io.BytesIO()
            response = self.api_client.download_file(hash_value, bytes_obj)
            bytes_obj.seek(0)
            file_contents = bytes_obj.read()

            mime_type = magic.from_buffer(file_contents, mime=True)

            # Upload the file as an Artifact
            kwargs = {
                "file_name": hash_value,
                "data": file_contents,
                "mime_type": mime_type,
                "x_opencti_description": f"Downloaded from Virustotal via hash {hash_value}",
            }
            response = self.helper.api.stix_cyber_observable.upload_artifact(**kwargs)

            self.helper.log_info(response)

            artifact_id = response["standard_id"]

        except Exception as e:
            raise Exception(
                f"Failed to download/upload Artifact with hash {hash_value}, exception: {e}"
            )

        # Create a relationship between the StixFile and the new Artifact
        relationship = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="related-to",
            created_by_ref=self.identity,
            source_ref=observable["standard_id"],
            target_ref=artifact_id,
            allow_custom=True,
        )
        bundle_objects.append(relationship)

        if bundle_objects:
            bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        else:
            return "Nothing to attach"

    def _process_observable(self, observable):
        self.helper.log_info(
            "Processing the observable " + observable["observable_value"]
        )

        if observable["entity_type"] == "StixFile":
            return self._process_hash(observable)
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
        return self._process_observable(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        virustotal_downloader = VirustotalDownloaderConnector()
        virustotal_downloader.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
