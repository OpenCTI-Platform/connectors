import json
import os
import time
from datetime import datetime
from typing import Dict

import stix2
from lib.internal_enrichment import InternalEnrichmentConnector
from pycti import (
    STIX_EXT_OCTI_SCO,
    Identity,
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from ReversingLabs.SDK.a1000 import A1000

ZIP_MIME_TYPES = (
    "application/x-bzip",
    "application/x-bzip2",
    "application/gzip",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-7z-compressed",
)
TRUE_LIST = ("true", "True", "yes", "Yes")
FALSE_LIST = ("false", "False", "no", "No")
PLATFORM_LIST = ("windows7", "windows10", "windows11", "macos11", "linux")
FILE_SAMPLE = ("Artifact", "StixFile", "File")


class ReversingLabsSpectraAnalyzeConnector(InternalEnrichmentConnector):

    def __init__(self):
        super().__init__()
        self._get_config_variables()
        # ReversingLabs identity
        self.reversinglabs_identity = self.helper.api.identity.create(
            type="Organization",
            name="ReversingLabs",
            description="www.reversinglabs.com",
        )

    def _get_config_variables(self):

        self.helper.log_info(
            f"{self.helper.connect_name}: Reading configuration env variables!"
        )

        self.connector_name = os.environ.get("CONNECTOR_NAME", None)
        self.opencti_url = os.environ.get("OPENCTI_URL", None)
        self.opencti_token = os.environ.get("OPENCTI_TOKEN", None)
        self.reversinglabs_spectra_analyze_url = os.environ.get(
            "REVERSINGLABS_SPECTRA_ANALYZE_URL", None
        )
        self.reversinglabs_spectra_analyze_token = os.environ.get(
            "REVERSINGLABS_SPECTRA_ANALYZE_TOKEN", None
        )
        self.reversinglabs_max_tlp = os.environ.get("REVERSINGLABS_MAX_TLP", None)
        self.reversinglabs_sandbox_platform = os.environ.get("REVERSINGLABS_SANDBOX_OS")
        self.reversinglabs_create_indicators = os.environ.get(
            "REVERSINGLABS_CREATE_INDICATORS"
        )
        self.reversinglabs_cloud_analysis = os.environ.get(
            "REVERSINGLABS_CLOUD_ANALYSIS"
        )

        self.reversinglabs_spectra_user_agent = (
            "ReversingLabs Spectra Analyze OpenCTI v1.0.0"
        )

    """
    Extract TLP and check if max_tlp is less than or equal to the marking access
    of the entity. If true we can send data for enrichment.
    """

    def _check_tlp_markings(self, entity):
        tlp = "TLP:CLEAR"
        for marking_definition in entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

            if not OpenCTIConnectorHelper.check_max_tlp(
                tlp, self.reversinglabs_max_tlp
            ):
                raise ValueError(
                    f"{self.helper.connect_name}: ERROR: Do not send any data, TLP of the observable is greater than MAX TLP"
                )
        return tlp

    def _generate_stix_bundle(self, stix_objects, stix_entity):
        self.stix_objects = stix_objects
        self.stix_entity = stix_entity

        uniq_bundles_objects = list(
            {obj["id"]: obj for obj in self.stix_objects}.values()
        )
        self.helper.log_info(
            f"{self.helper.connect_name}: Number of Stix bundles to be enriched: {len(uniq_bundles_objects)}"
        )
        return self.helper.stix2_create_bundle(uniq_bundles_objects)

    def _generate_stix_identity(self, stix_objects):
        self.stix_objects = stix_objects
        organization = "ReversingLabs"

        stix_organization = stix2.Identity(
            id=Identity.generate_id(organization, "Organization"),
            name=organization,
            identity_class="organization",
            created_by_ref=self.reversinglabs_identity["standard_id"],
        )
        self.stix_objects.append(stix_organization)

    def _upload_file_to_spectra_analyze(self, file_uri, is_archive, sample_name):
        file_content = self.helper.api.fetch_opencti_file(file_uri, binary=True)
        report = {}

        file = open(sample_name, "wb")
        file.write(file_content)
        file.close()

        # Submit File for Analysis
        self.helper.log_info(
            f"{self.helper.connect_name}: Submitting artifact {str(sample_name)} to ReversingLabs Spectra Analyze."
        )

        if self.reversinglabs_cloud_analysis in TRUE_LIST:
            cloud_analysis = True
        else:
            cloud_analysis = False

        try:
            response = self.a1000client.upload_sample_and_get_detailed_report_v2(
                file_path=sample_name,
                custom_filename=sample_name,
                cloud_analysis=cloud_analysis,
                rl_cloud_sandbox_platform=self.reversinglabs_sandbox_platform,
                comment="Uploaded from OpenCTI Platform",
                tags="opencti",
            )

            if response.status_code == 200:
                report = response.text
            else:
                self.helper.log_info(
                    f"{self.helper.connect_name}: There was issue with getting report from Spectra Analyze. HTTP Status code {str(response.status_code)}"
                )
                os.remove(sample_name)

        except Exception as err:
            raise ValueError(
                f"{self.helper.connect_name}: Looks like the sample you are trying to access may not be available on your Spectra Analyze instance. On Spectra Analyze run fetch and analyze on the sample."
            ) from err

        # Remove File from Os
        os.remove(sample_name)
        return report

    def _submit_file_for_analysis(self, stix_entity, opencti_entity, hash, hash_type):
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.hash = hash
        self.hash_type = hash_type
        analysis_report = {}

        if stix_entity["x_opencti_type"] == "Artifact":
            sample_name = self.opencti_entity["importFiles"][0]["name"]
            file_id = self.opencti_entity["importFiles"][0]["id"]
            file_mime_type = self.opencti_entity["mime_type"]
            file_uri = f"{self.helper.opencti_url}/storage/get/{file_id}"

            if file_mime_type in ZIP_MIME_TYPES:
                is_archive = True
            else:
                is_archive = False

            analysis_response = self._upload_file_to_spectra_analyze(
                file_uri, is_archive, sample_name
            )
            analysis_report = json.loads(analysis_response)

            if bool(analysis_report):
                self.helper.log_info(
                    f"{self.helper.connect_name}: File is successfully submitted to RL Spectra Analyze."
                )
            else:
                self.helper.log_info(
                    f"{self.helper.connect_name}: There was an issue with a file submit to RL Spectra Analyze."
                )
                raise ValueError(
                    f"{self.helper.connect_name}: Skipping Analysis processing due to issue with file upload!"
                )
        elif stix_entity["x_opencti_type"] == "StixFile":
            sample_name = self.opencti_entity["observable_value"]
            file_mime_type = "None"
            is_archive = False

            try:
                response = self.a1000client.get_detailed_report_v2(
                    sample_hashes=self.hash,
                    retry=True,
                )

                if response.status_code == 200:
                    analysis_report = json.loads(response.text)
                else:
                    raise Exception(
                        f"{self.helper.connect_name}: There was issue with getting report from Spectra Analyze. HTTP Status code {str(response.status_code)}"
                    )
            except Exception as err:
                raise ValueError(
                    f"{self.helper.connect_name}: Looks like the sample you are trying to access may not be available on your Spectra Analyze instance. On Spectra Analyze run fetch and analyze on the sample."
                ) from err
        else:
            raise ValueError(
                f"{self.helper.connect_name}: Unsupported type provided for analysis result retrieval!"
            )

        return analysis_report

    def _submit_url_for_analysis(self, stix_entity, opencti_entity, url_sample):
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.url = url_sample
        analysis_report = {}
        platform = self.reversinglabs_sandbox_platform

        if self.reversinglabs_cloud_analysis in TRUE_LIST:
            crawler = "cloud"
        else:
            crawler = "local"

        response = self.a1000client.submit_url_for_analysis(
            url_string=self.url,
            crawler=crawler,
            rl_cloud_sandbox_platform=platform,
        )
        # Parse TASK ID out of response
        response_json = json.loads(response.text)
        task_id = response_json["detail"]["id"]
        self.helper.log_info(
            f"{self.helper.connect_name}: Successfully submitted for analysis. Received task_id is {str(task_id)}"
        )

        self.helper.log_info(
            f"{self.helper.connect_name}: Fetching submitted url status from Spectra Analyze."
        )
        for retry in range(0, 5):
            # Check Submitted url status
            url_processing_status = self.a1000client.check_submitted_url_status(
                task_id=str(task_id),
            )

            analysis_status = json.loads(url_processing_status.text)
            processing_status = analysis_status["processing_status"]

            if processing_status != "complete":
                self.helper.log_info(
                    f"{self.helper.connect_name}: Processing status is {str(processing_status)}. Wait for 2min and retry..."
                )
                time.sleep(120)
            else:
                self.helper.log_info(
                    f"{self.helper.connect_name}: Report is successfully obtained!"
                )
                analysis_report = analysis_status
                continue

        return analysis_report

    def _process_file_analysis_result(
        self, stix_objects, stix_entity, opencti_entity, analysis_result
    ):
        self.stix_objects = stix_objects
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.analysis_result = analysis_result["results"][0]

        results = {}
        results["labels"] = []

        try:
            results["sample_name"] = self.analysis_result["aliases"][0]
            results["classification"] = self.analysis_result["classification"]
            results["sha256"] = self.analysis_result["sha256"]
            if (
                results["classification"] == "suspicious"
                or results["classification"] == "malicious"
            ):
                threat_name = self.analysis_result["classification_result"].split(".")
                results["threat_name"] = threat_name
                results["platform"] = threat_name[0]
                results["threat_type"] = threat_name[1]
                results["malware_family_name"] = threat_name[2]
                # Creating label out of malware type and family
                results["labels"].append(results["threat_type"])
                results["labels"].append(results["malware_family_name"])
            results["file_size"] = self.analysis_result["file_size"]
            results["file_type"] = self.analysis_result["file_type"]
            results["risk_score"] = self.analysis_result["riskscore"]
            results["score"] = results["risk_score"] * 10
            results["story"] = self.analysis_result["ticore"]["story"]
            results["description"] = (
                "Sample was processed by Spectra Analyze! Sample is classified as "
                + results["classification"]
                + ".File type: "
                + results["file_type"]
                + "\nFile size: "
                + str(results["file_size"])
                + " B. "
                + results["story"]
            )

            # Creating label out of classification
            results["labels"].append(results["classification"])

        except Exception as err:
            raise ValueError(
                f"{self.helper.connect_name}: INFO: Fetching analysis data failed. Please try again shortly!"
            ) from err

        # Add score and description to the Observable
        self._upsert_observable(results)

        return results

    def _process_url_analysis_result(
        self, stix_objects, stix_entity, opencti_entity, analysis_result
    ):
        self.stix_objects = stix_objects
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.analysis_result = analysis_result["report"]

        results = {}
        results["labels"] = []

        try:
            results["sample_name"] = self.analysis_result["networkthreatintelligence"][
                "requested_url"
            ]
            results["classification"] = self.analysis_result["classification"]
            results["sha256"] = self.analysis_result["sha256"]
            if (
                results["classification"] == "suspicious"
                or results["classification"] == "malicious"
            ):
                threat_name = self.analysis_result["classification_result"].split(".")
                results["threat_name"] = threat_name
                results["platform"] = threat_name[0]
                results["threat_type"] = threat_name[1]
                results["malware_family_name"] = threat_name[2]
                # Creating label out of malware type and family
                results["labels"].append(results["threat_type"])
                results["labels"].append(results["malware_family_name"])
            results["file_size"] = self.analysis_result["file_size"]
            results["file_type"] = self.analysis_result["file_type"]
            results["risk_score"] = self.analysis_result["riskscore"]
            results["score"] = results["risk_score"] * 10
            results["story"] = self.analysis_result["ticore"]["story"]
            results["description"] = (
                "Sample was processed by Spectra Analyze! Sample is classified as "
                + results["classification"]
                + ".File type: "
                + results["file_type"]
                + "\n File size: "
                + str(results["file_size"])
                + " B. "
                + results["story"]
            )

            # Creating label out of classification
            results["labels"].append(results["classification"])

        except Exception as err:
            raise ValueError(
                f"{self.helper.connect_name}: INFO: Fetching analysis data failed. Please try again shortly!"
            ) from err

        # Add score and description to the Observable
        self._upsert_observable(results)

        return results

    def _upsert_observable(self, results):
        risk_score = results["risk_score"] * 10
        score = self._generate_score(risk_score)
        labels = results["labels"]
        description = results["description"]

        # Upsert artifact score
        self.helper.api.stix_cyber_observable.update_field(
            id=self.stix_entity["id"],
            input={
                "key": "x_opencti_score",
                "value": score,
            },
        )

        # Upsert artifact description
        self.helper.api.stix_cyber_observable.update_field(
            id=self.stix_entity["id"],
            input={
                "key": "x_opencti_description",
                "value": description,
            },
        )

        # Upsert artifact labels
        for lab in labels:
            if not ((lab == "Unknown") or (lab == "")):
                label = self.helper.api.label.create(
                    value=lab,
                )
                self.helper.api.stix_cyber_observable.add_label(
                    id=self.stix_entity["id"],
                    label_id=label["id"],
                )

    def _generate_score(self, score):
        self.helper.api.stix2.put_attribute_in_extension(
            self.stix_entity, STIX_EXT_OCTI_SCO, "x_opencti_score", score, True
        )
        return score

    def _create_indicators(self, results):
        self.helper.log_info(
            f"{self.helper.connect_name}: Generating indicators based on the classification"
        )

        indicator_name = results["sample_name"]
        relationship = "based-on"

        if self.stix_entity["x_opencti_type"] != "Url":
            indicator_sha256 = results["sha256"]
            indicator_pattern = f"[file:hashes. 'SHA-256' = '{indicator_sha256}']"
            main_observable_type = "File"
        elif self.stix_entity["x_opencti_type"] == "Url":
            indicator_pattern = f"[url:value = '{indicator_name}']"
            main_observable_type = "Url"
        else:
            raise ValueError(
                f"{self.helper.connect_name}: Unsupported type for creating indicators!"
            )

        # Create Indicator and add relationship to observable
        self._generate_stix_indicator(
            results,
            indicator_name,
            indicator_pattern,
            main_observable_type,
            relationship,
        )

    def _generate_stix_malware(self, results):
        stix_malware_with_relationship = []
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

        if not (
            (results["malware_family_name"] == "generic")
            or (results["malware_family_name"] == "unknown")
        ):
            # Create malware
            stix_malware = stix2.Malware(
                id=Malware.generate_id(results["malware_family_name"]),
                created=now,
                name=results["malware_family_name"],
                description="ReversingLabs",
                is_family="false",
                created_by_ref=self.reversinglabs_identity["standard_id"],
            )
            self.stix_objects.append(stix_malware)
            stix_malware_with_relationship.append(stix_malware)

            # Generate Relationship : artifact -> "related-to" -> Malware
            observable_to_malware = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_malware.id
            )

            self.stix_objects.append(observable_to_malware)
            stix_malware_with_relationship.append(observable_to_malware)

    def _generate_stix_indicator(
        self,
        results,
        indicator_name,
        indicator_pattern,
        main_observable_type,
        relationship,
    ):
        stix_indicator_with_relationship = []
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        rl_threat_platform = results["platform"]

        # Create indicator
        stix_indicator = stix2.Indicator(
            id=Indicator.generate_id(indicator_name),
            name=indicator_name,
            description=results["description"],
            labels=results["labels"],
            pattern=indicator_pattern,
            created_by_ref=self.reversinglabs_identity["standard_id"],
            valid_from=now,
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={
                "pattern_type": "stix",
                "x_opencti_score": results["score"],
                "x_opencti_main_observable_type": main_observable_type,
                "x_mitre_platforms": f"{rl_threat_platform}",
                "detection": True,
            },
        )

        self.stix_objects.append(stix_indicator)
        stix_indicator_with_relationship.append(stix_indicator)

        # Generate Relationship Indicator -> Based on -> Artifact
        indicator_to_observable = self._generate_stix_relationship(
            stix_indicator.id, relationship, self.stix_entity["id"]
        )

        self.stix_objects.append(indicator_to_observable)
        stix_indicator_with_relationship.append(indicator_to_observable)

    def _generate_stix_relationship(
        self, source_ref, stix_core_relationship_type, target_ref
    ):
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=self.reversinglabs_identity["standard_id"],
            object_marking_refs=[stix2.TLP_AMBER],
        )

    def _process_message(self, data: Dict):
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        self.helper.log_info(
            f"{self.helper.connect_name}: Checking TLP marking on object."
        )

        self._check_tlp_markings(opencti_entity)
        opencti_type = stix_entity["x_opencti_type"]

        # Generate Identity (Organization)
        self._generate_stix_identity(stix_objects)

        # Create A1k client
        self.a1000client = A1000(
            host=self.reversinglabs_spectra_analyze_url,
            token=self.reversinglabs_spectra_analyze_token,
            user_agent=self.reversinglabs_spectra_user_agent,
            verify=False,
        )

        results = {}

        if opencti_type in FILE_SAMPLE:
            # Extract hash type and value from entity {[md5], [sha1], [sha256]}
            hashes = opencti_entity.get("hashes")
            for ent_hash in hashes:
                if not (
                    (ent_hash["algorithm"] == "MD5")
                    or (ent_hash["algorithm"] == "SHA-512")
                ):
                    hash = ent_hash["hash"]
                    hash_type = ent_hash["algorithm"]

            # Submit File sample for analysis
            analysis_result = self._submit_file_for_analysis(
                stix_entity, opencti_entity, hash, hash_type
            )

            if not analysis_result:
                raise ValueError(
                    f"{self.helper.connect_name}: Provided sample does not exist on the appliance. Try to upload it first and re-run!"
                )

            # Integrate analysis results with OpenCTI
            results = self._process_file_analysis_result(
                stix_objects, stix_entity, opencti_entity, analysis_result
            )

        elif opencti_type == "Url":
            url_sample = stix_entity["value"]
            self.helper.log_info(
                f"{self.helper.connect_name}: Submit URL sample for analysis on Spectra Analyze!"
            )
            # Submit URL sample for analysis on Spectra Analyze
            analysis_result = self._submit_url_for_analysis(
                stix_entity,
                opencti_entity,
                url_sample,
            )

            if not analysis_result:
                raise ValueError(
                    f"{self.helper.connect_name}: Provided sample does not exist on the appliance. Try to upload it first and re-run!"
                )

            # Integrate analysis results with OpenCTI
            results = self._process_url_analysis_result(
                stix_objects, stix_entity, opencti_entity, analysis_result
            )

        else:
            raise ValueError(
                f"{self.helper.connect_name}: Connector is not registered to work with provided {str(opencti_type)} type!"
            )

        if (results["classification"] == "malicious") or (
            results["classification"] == "suspicious"
        ):

            # Create indicators based on result
            self._create_indicators(results)

            # Create Malware and add relationship to artifact
            self._generate_stix_malware(results)

            # Create Stix Bundle and send it to OpenCTI
            bundle = self._generate_stix_bundle(stix_objects, stix_entity)
            bundles_sent = self.helper.send_stix2_bundle(bundle)

            self.helper.log_info(
                f"{self.helper.connect_name}: Number of stix bundles sent for workers: {str(len(bundles_sent))}"
            )


if __name__ == "__main__":
    connector = ReversingLabsSpectraAnalyzeConnector()
    connector.start()
