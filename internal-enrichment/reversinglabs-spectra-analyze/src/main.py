# Standard library imports
import json
import os
import textwrap
import time
from datetime import datetime
from functools import wraps
from typing import Dict

import stix2
from lib.internal_enrichment import InternalEnrichmentConnector
from pycti import (
    STIX_EXT_OCTI_SCO,
    Identity,
    Indicator,
    Malware,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from ReversingLabs.SDK.a1000 import A1000
from ReversingLabs.SDK.helper import NotFoundError, RequestTimeoutError

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


# decorator wrapper
def handle_spectra_errors(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except NotFoundError:
            self.helper.connector_logger.warning(
                f"{self.helper.connect_name}: Detailed analysis report not found. Falling back to classification result."
            )
            return None
        except RequestTimeoutError as err:
            self.helper.connector_logger.error(
                f"{self.helper.connect_name}: Timeout error occurred while communicating with Spectra Analyze: {err}"
            )
            raise TimeoutError(
                f"{self.helper.connect_name}: Request timed out. The endpoint might be down. Please try again later."
            ) from err
        except Exception as err:
            self.helper.connector_logger.error(
                f"{self.helper.connect_name}: Unexpected error during Spectra Analyze call: {err}"
            )
            raise RuntimeError(
                f"{self.helper.connect_name}: Looks like the sample you are trying to access may not be available on your Spectra Analyze instance. On Spectra Analyze run fetch and analyze on the sample."
            ) from err

    return wrapper


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

        self.helper.connector_logger.info(
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
            "ReversingLabs Spectra Analyze OpenCTI v1.2.0"
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
        self.helper.connector_logger.info(
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

    @handle_spectra_errors
    def _upload_file_to_spectra_analyze(self, file_uri, is_archive, sample_name):
        file_content = self.helper.api.fetch_opencti_file(file_uri, binary=True)
        report = {}

        file = open(sample_name, "wb")
        file.write(file_content)
        file.close()

        # Submit File for Analysis
        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Submitting artifact {str(sample_name)} to ReversingLabs Spectra Analyze."
        )

        if self.reversinglabs_cloud_analysis in TRUE_LIST:
            cloud_analysis = True
        else:
            cloud_analysis = False

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
            self.helper.connector_logger.info(
                f"{self.helper.connect_name}: There was issue with getting report from Spectra Analyze. "
                f"HTTP Status code {response.status_code}"
            )
        try:
            os.remove(sample_name)
        except FileNotFoundError:
            self.helper.connector_logger.warning(
                f"{self.helper.connect_name}: Temp sample file not found when deleting."
            )
        except Exception as err:
            self.helper.connector_logger.error(
                f"{self.helper.connect_name}: Failed deleting temp sample file : {err}"
            )

        return report

    @handle_spectra_errors
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

            is_archive = file_mime_type in ZIP_MIME_TYPES
            analysis_response = self._upload_file_to_spectra_analyze(
                file_uri, is_archive, sample_name
            )
            analysis_report = json.loads(analysis_response) if analysis_response else {}

        elif stix_entity["x_opencti_type"] == "StixFile":
            sample_name = self.opencti_entity["observable_value"]
            response = self.a1000client.get_detailed_report_v2(
                sample_hashes=self.hash, retry=False
            )
            if response.status_code == 404:
                raise NotFoundError(f"Sample with hash {self.hash} not found.")
            analysis_report = json.loads(response.text)

        else:
            raise ValueError(
                f"{self.helper.connect_name}: Unsupported type provided for analysis result retrieval!"
            )

        return analysis_report

    @handle_spectra_errors
    def _submit_file_for_classification(self, stix_entity, opencti_entity, hash):
        """
        Submit the file for classification, with error handling.
        """
        response = self.a1000client.get_classification_v3(
            sample_hash=hash, local_only=False, av_scanners=False
        )
        return json.loads(response.text)

    @handle_spectra_errors
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
            f"{self.helper.connect_name}: Successfully submitted for analysis. Received task_id is {task_id}"
        )

        self.helper.log_info(
            f"{self.helper.connect_name}: Fetching submitted url status from Spectra Analyze."
        )
        for retry in range(5):
            # Check Submitted url status
            url_processing_status = self.a1000client.check_submitted_url_status(
                task_id=str(task_id),
            )

            analysis_status = json.loads(url_processing_status.text)
            processing_status = analysis_status["processing_status"]

            if processing_status != "complete":
                self.helper.log_info(
                    f"{self.helper.connect_name}: Processing status is {processing_status}. Wait for 2min and retry..."
                )
                time.sleep(120)
            else:
                self.helper.log_info(
                    f"{self.helper.connect_name}: Report is successfully obtained!"
                )
                analysis_report = analysis_status
                # we can break here since we got the report
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
            if results["classification"] in ("suspicious", "malicious"):
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

    def _process_file_classification_results(
        self, stix_objects, stix_entity, opencti_entity, analysis_result
    ):
        self.stix_objects = stix_objects
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.analysis_result = analysis_result

        results = {}
        results["labels"] = []

        try:
            results["sample_name"] = self.analysis_result["sha1"]
            results["classification"] = self.analysis_result["classification"]
            results["sha256"] = self.analysis_result["sha256"]
            if results["classification"] in ("suspicious", "malicious"):
                threat_name = self.analysis_result["classification_result"].split(".")
                results["threat_name"] = threat_name
                results["platform"] = threat_name[0]
                results["threat_type"] = threat_name[1]
                results["malware_family_name"] = threat_name[2]
                # Creating label out of malware type and family
                results["labels"].append(results["threat_type"])
                results["labels"].append(results["malware_family_name"])
            results["risk_score"] = self.analysis_result["riskscore"]
            results["score"] = results["risk_score"] * 10
            results["description"] = (
                "Sample was processed by Spectra Analyze! Sample is classified as "
                + results["classification"]
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
        self.helper.connector_logger.info(
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
        rl_threat_platform = results["platform"]

        # Create indicator
        stix_indicator = stix2.Indicator(
            id=Indicator.generate_id(indicator_name),
            name=indicator_name,
            description=results["description"],
            labels=results["labels"],
            pattern=indicator_pattern,
            created_by_ref=self.reversinglabs_identity["standard_id"],
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

    @handle_spectra_errors
    def _files_from_ip(self):
        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Getting files from IP"
        )

        file_list = self.a1000client.network_files_from_ip_aggregated(
            ip_addr=self.ip_sample, classification="MALICIOUS", max_results=20
        )

        if not file_list:
            file_list = self.a1000client.network_files_from_ip_aggregated(
                ip_addr=self.ip_sample, max_results=20
            )

        for one_file in file_list:
            sha1 = one_file.get("sha1")
            download_url = one_file.get("last_download_url")
            classification = one_file.get("classification")
            malware_family = one_file.get("malware_family")
            malware_type = one_file.get("malware_type")
            labels = [
                label
                for label in (classification, malware_family, malware_type)
                if label
            ]
            now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            platform = one_file.get("platform", "")
            risk_score = int(one_file.get("risk_score")) * 10
            description = (
                f"Created from files downloaded from an IP address by Spectra Analyze. The indicator is"
                f"classified as {classification}."
            )
            if classification in ("MALICIOUS", "SUSPICIOUS"):
                description += f" Threat name is {one_file.get('threat_name')}"

            indicator_sha1 = stix2.Indicator(
                id=Indicator.generate_id(sha1),
                name=sha1,
                description=description,
                labels=labels,
                pattern=f"[file:hashes. 'SHA-1' = '{sha1}']",
                created_by_ref=self.reversinglabs_identity["standard_id"],
                object_marking_refs=[stix2.TLP_AMBER],
                custom_properties={
                    "pattern_type": "stix",
                    "x_opencti_score": risk_score,
                    "x_opencti_main_observable_type": "IPv4-Addr",
                    "x_mitre_platforms": f"{platform}",
                    "detection": True,
                },
            )
            self.stix_objects.append(indicator_sha1)

            indicator_download_url = stix2.Indicator(
                id=Indicator.generate_id(download_url),
                name=download_url,
                description=description,
                labels=labels,
                pattern=f"[url:value = '{download_url}']",
                created_by_ref=self.reversinglabs_identity["standard_id"],
                object_marking_refs=[stix2.TLP_AMBER],
                custom_properties={
                    "pattern_type": "stix",
                    "x_opencti_score": risk_score,
                    "x_opencti_main_observable_type": "IPv4-Addr",
                    "x_mitre_platforms": f"{platform}",
                    "detection": True,
                },
            )
            self.stix_objects.append(indicator_download_url)

            sha1_to_observable = self._generate_stix_relationship(
                source_ref=indicator_sha1.id,
                stix_core_relationship_type="based-on",
                target_ref=self.stix_entity["id"],
            )
            self.stix_objects.append(sha1_to_observable)

            download_url_to_observable = self._generate_stix_relationship(
                source_ref=indicator_download_url.id,
                stix_core_relationship_type="based-on",
                target_ref=self.stix_entity["id"],
            )
            self.stix_objects.append(download_url_to_observable)

            sha1_to_download_url = self._generate_stix_relationship(
                source_ref=indicator_sha1.id,
                stix_core_relationship_type="related-to",
                target_ref=indicator_download_url.id,
            )
            self.stix_objects.append(sha1_to_download_url)

            if classification in ("MALICIOUS", "SUSPICIOUS"):
                malware = stix2.Malware(
                    id=Malware.generate_id(malware_family),
                    name=malware_family,
                    created=now,
                    description="ReversingLabs",
                    malware_types=[malware_type],
                    is_family="false",
                    created_by_ref=self.reversinglabs_identity["standard_id"],
                )
                self.stix_objects.append(malware)

                sha1_to_malware = self._generate_stix_relationship(
                    source_ref=indicator_sha1.id,
                    stix_core_relationship_type="related-to",
                    target_ref=malware.id,
                )
                self.stix_objects.append(sha1_to_malware)

                download_url_to_malware = self._generate_stix_relationship(
                    source_ref=indicator_download_url.id,
                    stix_core_relationship_type="related-to",
                    target_ref=malware.id,
                )
                self.stix_objects.append(download_url_to_malware)

    @handle_spectra_errors
    def _ip_report(self):
        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Getting IP report"
        )

        response = self.a1000client.network_ip_addr_report(ip_addr=self.ip_sample)

        resp_json = response.json()

        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        tp_statistics = resp_json.get("third_party_reputations", {}).get(
            "statistics", {}
        )
        dl_files_statistics = resp_json.get("downloaded_files_statistics", {})
        abstract = "ReversingLabs Spectra Analyze IP address report"

        content = textwrap.dedent(
            f"""
        ## ReversingLabs Spectra Analyze IP address report for {self.ip_sample}
        Third party statistics
        | Status        |  Amount         |
        | ------------- | --------------- |
        | MALICIOUS     | {tp_statistics.get('malicious')} |
        | CLEAN         | {tp_statistics.get('clean')} |
        | SUSPICIOUS    | {tp_statistics.get('suspicious')} |
        | UNDETECTED    | {tp_statistics.get('undetected')} |
        | TOTAL         | {tp_statistics.get('total')} |
        
        Downloaded files statistics
        | Status        |  Amount         |
        | ------------- | --------------- |
        | MALICIOUS     | {dl_files_statistics.get('malicious')} |
        | GOODWARE      | {dl_files_statistics.get('goodware')} |
        | SUSPICIOUS    | {dl_files_statistics.get('suspicious')} |
        | UNKNOWN       | {dl_files_statistics.get('unknown')} |
        | TOTAL         | {dl_files_statistics.get('total')} |
        """
        )

        note = stix2.Note(
            id=Note.generate_id(now, content),
            abstract=abstract,
            content=content,
            created_by_ref=self.reversinglabs_identity["standard_id"],
            object_refs=[self.stix_entity["id"]],
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={"note_types": ["external"]},
        )
        self.stix_objects.append(note)

        self.helper.api.stix_cyber_observable.update_field(
            id=self.stix_entity["id"],
            input={
                "key": "x_opencti_description",
                "value": "This is an IP address observable enriched by Spectra Analyze.",
            },
        )

    @staticmethod
    def is_ip(address):
        return address.replace(".", "").isnumeric()

    @handle_spectra_errors
    def _domain_reports(self, domain_list):
        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Getting domain reports"
        )

        malicious_domains = []
        benign_domains = []
        malware_list = []
        malicious_exist = False

        for domain_obj in domain_list:
            domain = domain_obj.get("host_name")

            if self.is_ip(domain):
                continue

            response = self.a1000client.network_domain_report(domain=domain)
            resp_json = response.json()

            top_threats = resp_json.get("top_threats")
            dl_files_stats = resp_json.get("downloaded_files_statistics", {})
            tp_stats = resp_json.get("third_party_reputations", {}).get(
                "statistics", {}
            )

            if (
                top_threats
                or dl_files_stats.get("malicious") >= 3
                or tp_stats.get("malicious") >= 3
            ):
                malicious_domains.append(resp_json)

                if len(malicious_domains) >= 20:
                    break

                malicious_exist = True

            else:
                if not malicious_exist:
                    benign_domains.append(resp_json)

                    if len(benign_domains) >= 20:
                        break

        if malicious_exist:
            selected_domains = malicious_domains
            del benign_domains

        else:
            selected_domains = benign_domains
            del malicious_domains

        for one_domain in selected_domains:
            top_threats = one_domain.get("top_threats")
            now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            labels = []

            if malicious_exist:
                if top_threats:
                    for threat in top_threats:
                        threat_name_split = threat.get("threat_name").split(".")
                        labels = [threat_name_split[1], threat_name_split[2]]

                        for label in labels:
                            lbl = self.helper.api.label.create(value=label)
                            self.helper.api.stix_cyber_observable.add_label(
                                id=self.stix_entity["id"], label_id=lbl["id"]
                            )

                        malware = stix2.Malware(
                            id=Malware.generate_id(threat_name_split[2]),
                            name=threat_name_split[2],
                            created=now,
                            description="ReversingLabs",
                            malware_types=[threat_name_split[1]],
                            is_family="false",
                            created_by_ref=self.reversinglabs_identity["standard_id"],
                        )
                        malware_list.append(malware)
                        self.stix_objects.append(malware)

            indicator_domain = stix2.Indicator(
                id=Indicator.generate_id(one_domain.get("requested_domain")),
                name=one_domain.get("requested_domain"),
                description="Created from Spectra Analyze Domain report.",
                labels=labels,
                pattern=f"[domain-name:value = '{one_domain.get('requested_domain')}']",
                created_by_ref=self.reversinglabs_identity["standard_id"],
                object_marking_refs=[stix2.TLP_AMBER],
                custom_properties={
                    "pattern_type": "stix",
                    "x_opencti_main_observable_type": "IPv4-Addr",
                    "detection": True,
                },
            )
            self.stix_objects.append(indicator_domain)

            indicator_to_observable = self._generate_stix_relationship(
                source_ref=indicator_domain.id,
                stix_core_relationship_type="based-on",
                target_ref=self.stix_entity["id"],
            )
            self.stix_objects.append(indicator_to_observable)

            for mal in malware_list:
                indicator_to_malware = self._generate_stix_relationship(
                    source_ref=indicator_domain.id,
                    stix_core_relationship_type="related-to",
                    target_ref=mal.id,
                )
                self.stix_objects.append(indicator_to_malware)

        if selected_domains:
            abstract = "ReversingLabs Spectra Analyze domain statistics"

            accumulated_content = textwrap.dedent(
                """
            ## ReversingLabs Spectra Analyze domain statistics
            | Domain        |  Third party statistics Malicious/Total | Downloaded files statistics Malicious/Total |
            | ------------- | --------------- | --------------- |
            """
            )

            for one_domain in selected_domains:
                domain_name = one_domain.get("requested_domain")
                tp_stats = one_domain.get("third_party_reputations", {}).get(
                    "statistics", {}
                )
                dl_stats = one_domain.get("downloaded_files_statistics", {})

                accumulated_content = accumulated_content + textwrap.dedent(
                    f"| {domain_name} | {tp_stats['malicious']}/{tp_stats['total']} | {dl_stats['malicious']}/{dl_stats['total']} |\n"
                )

            content = accumulated_content

            now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

            note = stix2.Note(
                id=Note.generate_id(now, content),
                abstract=abstract,
                content=content,
                created_by_ref=self.reversinglabs_identity["standard_id"],
                object_refs=[self.stix_entity["id"]],
                object_marking_refs=[stix2.TLP_AMBER],
                custom_properties={"note_types": ["external"]},
            )
            self.stix_objects.append(note)

    @handle_spectra_errors
    def _url_reports(self, url_list):
        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Getting URL reports"
        )

        malicious_urls = []
        benign_urls = []
        malware_list = []
        malicious_exist = False

        for url_obj in url_list:
            url = url_obj.get("url")

            response = self.a1000client.network_url_report(requested_url=url)
            resp_json = response.json()

            classification = resp_json.get("classification")

            if classification == "malicious":
                malicious_urls.append(resp_json)

                if len(malicious_urls) >= 20:
                    break

                malicious_exist = True

            else:
                if not malicious_exist:
                    benign_urls.append(resp_json)

                    if len(benign_urls) >= 20:
                        break

        if malicious_exist:
            selected_urls = malicious_urls
            del benign_urls

        else:
            selected_urls = benign_urls
            del malicious_urls

        for one_url in selected_urls:
            top_threats = one_url.get("analysis").get("top_threats")
            now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            labels = []

            if malicious_exist:
                if top_threats:
                    for threat in top_threats:
                        threat_name_split = threat.get("threat_name").split(".")
                        labels = [threat_name_split[1], threat_name_split[2]]

                        for label in labels:
                            lbl = self.helper.api.label.create(value=label)
                            self.helper.api.stix_cyber_observable.add_label(
                                id=self.stix_entity["id"], label_id=lbl["id"]
                            )

                        malware = stix2.Malware(
                            id=Malware.generate_id(threat_name_split[2]),
                            name=threat_name_split[2],
                            created=now,
                            description="ReversingLabs",
                            malware_types=[threat_name_split[1]],
                            is_family="false",
                            created_by_ref=self.reversinglabs_identity["standard_id"],
                        )
                        malware_list.append(malware)
                        self.stix_objects.append(malware)

            indicator_url = stix2.Indicator(
                id=Indicator.generate_id(one_url.get("requested_url")),
                name=one_url.get("requested_url"),
                description="Created from Spectra Analyze URL report.",
                labels=labels,
                pattern=f"[url:value = '{one_url.get('requested_url')}']",
                created_by_ref=self.reversinglabs_identity["standard_id"],
                object_marking_refs=[stix2.TLP_AMBER],
                custom_properties={
                    "pattern_type": "stix",
                    "x_opencti_main_observable_type": "IPv4-Addr",
                    "detection": True,
                },
            )
            self.stix_objects.append(indicator_url)

            indicator_to_observable = self._generate_stix_relationship(
                source_ref=indicator_url.id,
                stix_core_relationship_type="based-on",
                target_ref=self.stix_entity["id"],
            )
            self.stix_objects.append(indicator_to_observable)

            for mal in malware_list:
                indicator_to_malware = self._generate_stix_relationship(
                    source_ref=indicator_url.id,
                    stix_core_relationship_type="related-to",
                    target_ref=mal.id,
                )
                self.stix_objects.append(indicator_to_malware)

        if selected_urls:
            abstract = "ReversingLabs Spectra Analyze URL statistics"

            accumulated_content = textwrap.dedent(
                """
            ## ReversingLabs Spectra Analyze URL statistics
            | URL        |  Third party statistics Malicious/Total | Analysis statistics Malicious/Total |
            | ------------- | --------------- | --------------- |
            """
            )

            for one_url in selected_urls:
                url_name = one_url.get("requested_url")
                tp_stats = one_url.get("third_party_reputations", {}).get(
                    "statistics", {}
                )
                analysis_stats = one_url.get("analysis", {}).get("statistics", {})

                accumulated_content = accumulated_content + textwrap.dedent(
                    f"| `{url_name}` | {tp_stats['malicious']}/{tp_stats['total']} | {analysis_stats['malicious']}/{analysis_stats['total']} |\n"
                )

            content = accumulated_content
            now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

            note = stix2.Note(
                id=Note.generate_id(now, content),
                abstract=abstract,
                content=content,
                created_by_ref=self.reversinglabs_identity["standard_id"],
                object_refs=[self.stix_entity["id"]],
                object_marking_refs=[stix2.TLP_AMBER],
                custom_properties={"note_types": ["external"]},
            )
            self.stix_objects.append(note)

    @handle_spectra_errors
    def _ip_report_flow(self, stix_entity, opencti_entity, ip_sample):
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.ip_sample = ip_sample

        self._files_from_ip()

        self._ip_report()

        domain_list = self.a1000client.network_ip_to_domain_aggregated(
            ip_addr=self.ip_sample, max_results=100
        )

        self._domain_reports(domain_list=domain_list)

        url_list = self.a1000client.network_urls_from_ip_aggregated(
            ip_addr=self.ip_sample, max_results=100
        )

        self._url_reports(url_list=url_list)

        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Creating bundle for IP"
        )

        bundle = self._generate_stix_bundle(
            stix_objects=self.stix_objects, stix_entity=self.stix_entity
        )
        bundles_sent = self.helper.send_stix2_bundle(bundle)

        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Number of stix bundles sent to workers: {str(len(bundles_sent))}"
        )

    @handle_spectra_errors
    def _domain_report(self):
        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Getting domain report"
        )

        response = self.a1000client.network_domain_report(domain=self.domain_sample)
        resp_json = response.json()

        top_threats = resp_json.get("top_threats")
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        malware_list = []
        labels = []

        if top_threats:
            for threat in top_threats:
                threat_name_split = threat.get("threat_name").split(".")
                labels = [threat_name_split[1], threat_name_split[2]]

                malware = stix2.Malware(
                    id=Malware.generate_id(threat_name_split[2]),
                    name=threat_name_split[2],
                    created=now,
                    description="ReversingLabs",
                    malware_types=[threat_name_split[1]],
                    is_family="false",
                    created_by_ref=self.reversinglabs_identity["standard_id"],
                )
                malware_list.append(malware)
                self.stix_objects.append(malware)

        indicator_domain = stix2.Indicator(
            id=Indicator.generate_id(self.domain_sample),
            name=self.domain_sample,
            description="Created from Spectra Analyze Domain report.",
            labels=labels,
            pattern=f"[domain-name:value = '{self.domain_sample}']",
            created_by_ref=self.reversinglabs_identity["standard_id"],
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={
                "pattern_type": "stix",
                "x_opencti_main_observable_type": "Domain-Name",
                "detection": True,
            },
        )
        self.stix_objects.append(indicator_domain)

        indicator_to_observable = self._generate_stix_relationship(
            source_ref=indicator_domain.id,
            stix_core_relationship_type="based-on",
            target_ref=self.stix_entity["id"],
        )
        self.stix_objects.append(indicator_to_observable)

        for mal in malware_list:
            indicator_to_malware = self._generate_stix_relationship(
                source_ref=indicator_domain.id,
                stix_core_relationship_type="related-to",
                target_ref=mal.id,
            )
            self.stix_objects.append(indicator_to_malware)

        abstract = "ReversingLabs Spectra Analyze domain report"

        tp_statistics = resp_json.get("third_party_reputations", {}).get(
            "statistics", {}
        )
        dl_files_statistics = resp_json.get("downloaded_files_statistics", {})

        content = textwrap.dedent(
            f"""
        ## ReversingLabs Spectra Analyze domain report for `{self.domain_sample}`
        Third party statistics
        | Status        |  Amount         |
        | ------------- | --------------- |
        | MALICIOUS     | {tp_statistics.get('malicious')} |
        | CLEAN         | {tp_statistics.get('clean')} |
        | SUSPICIOUS    | {tp_statistics.get('suspicious')} |
        | UNDETECTED    | {tp_statistics.get('undetected')} |
        | TOTAL         | {tp_statistics.get('total')} |
        
        Downloaded files statistics
        | Status        |  Amount         |
        | ------------- | --------------- |
        | MALICIOUS     | {dl_files_statistics.get('malicious')} |
        | GOODWARE      | {dl_files_statistics.get('goodware')} |
        | SUSPICIOUS    | {dl_files_statistics.get('suspicious')} |
        | UNKNOWN       | {dl_files_statistics.get('unknown')} |
        | TOTAL         | {dl_files_statistics.get('total')} |
        """
        )

        note = stix2.Note(
            id=Note.generate_id(now, content),
            abstract=abstract,
            content=content,
            created_by_ref=self.reversinglabs_identity["standard_id"],
            object_refs=[self.stix_entity["id"]],
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={"note_types": ["external"]},
        )
        self.stix_objects.append(note)

        self.helper.api.stix_cyber_observable.update_field(
            id=self.stix_entity["id"],
            input={
                "key": "x_opencti_description",
                "value": "This is a domain name observable enriched by Spectra Analyze.",
            },
        )

    def _domain_analysis_flow(self, stix_entity, opencti_entity, domain_sample):
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.domain_sample = domain_sample

        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Starting Domain report for {self.domain_sample}"
        )

        self._domain_report()

        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Creating bundle for domain"
        )

        bundle = self._generate_stix_bundle(
            stix_objects=self.stix_objects, stix_entity=self.stix_entity
        )
        bundles_sent = self.helper.send_stix2_bundle(bundle)

        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Number of stix bundles sent to workers: {str(len(bundles_sent))}"
        )

    @handle_spectra_errors
    def _url_report(self):
        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Getting URL report"
        )

        response = self.a1000client.network_url_report(requested_url=self.url_sample)
        resp_json = response.json()

        top_threats = resp_json.get("analysis", {}).get("top_threats")
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        malware_list = []
        labels = []

        if top_threats:
            for threat in top_threats:
                threat_name_split = threat.get("threat_name").split(".")
                labels = [threat_name_split[1], threat_name_split[2]]

                malware = stix2.Malware(
                    id=Malware.generate_id(threat_name_split[2]),
                    name=threat_name_split[2],
                    created=now,
                    description="ReversingLabs",
                    malware_types=[threat_name_split[1]],
                    is_family="false",
                    created_by_ref=self.reversinglabs_identity["standard_id"],
                )
                malware_list.append(malware)
                self.stix_objects.append(malware)

        indicator_url = stix2.Indicator(
            id=Indicator.generate_id(self.url_sample),
            name=self.url_sample,
            description="Created from Spectra Analyze URL report.",
            labels=labels,
            pattern=f"[url:value = '{self.url_sample}']",
            created_by_ref=self.reversinglabs_identity["standard_id"],
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={
                "pattern_type": "stix",
                "x_opencti_main_observable_type": "Url",
                "detection": True,
            },
        )
        self.stix_objects.append(indicator_url)

        indicator_to_observable = self._generate_stix_relationship(
            source_ref=indicator_url.id,
            stix_core_relationship_type="based-on",
            target_ref=self.stix_entity["id"],
        )
        self.stix_objects.append(indicator_to_observable)

        for mal in malware_list:
            indicator_to_malware = self._generate_stix_relationship(
                source_ref=indicator_url.id,
                stix_core_relationship_type="related-to",
                target_ref=mal.id,
            )
            self.stix_objects.append(indicator_to_malware)

        abstract = "ReversingLabs Spectra Analyze URL report"

        analysis_stats = resp_json.get("analysis", {}).get("statistics", {})
        tp_stats = resp_json.get("third_party_reputations", {}).get("statistics", {})

        content = textwrap.dedent(
            f"""
        ## ReversingLabs Spectra Analyze URL report for `{self.url_sample}`

        Third party statistics
        | Status        |  Amount         |
        | ------------- | --------------- |
        | MALICIOUS     | {tp_stats.get('malicious')} |
        | CLEAN         | {tp_stats.get('clean')} |
        | SUSPICIOUS    | {tp_stats.get('suspicious')} |
        | UNDETECTED    | {tp_stats.get('undetected')} |
        | TOTAL         | {tp_stats.get('total')} |
        
        Analysis statistics
        | Status        |  Amount         |
        | ------------- | --------------- |
        | MALICIOUS     | {analysis_stats.get('malicious')} |
        | GOODWARE      | {analysis_stats.get('goodware')} |
        | SUSPICIOUS    | {analysis_stats.get('suspicious')} |
        | UNKNOWN       | {analysis_stats.get('unknown')} |
        | TOTAL         | {analysis_stats.get('total')} |
        """
        )

        note = stix2.Note(
            id=Note.generate_id(now, content),
            abstract=abstract,
            content=content,
            created_by_ref=self.reversinglabs_identity["standard_id"],
            object_refs=[self.stix_entity["id"]],
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={"note_types": ["external"]},
        )
        self.stix_objects.append(note)

    def _url_report_flow(self, stix_entity, opencti_entity, url_sample):
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.url_sample = url_sample

        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Starting URL report for {self.url_sample}"
        )

        self._url_report()

        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Creating bundle for URL"
        )

        bundle = self._generate_stix_bundle(
            stix_objects=self.stix_objects, stix_entity=self.stix_entity
        )
        bundles_sent = self.helper.send_stix2_bundle(bundle)

        self.helper.connector_logger.info(
            f"{self.helper.connect_name}: Number of stix bundles sent to workers round 1: {str(len(bundles_sent))}"
        )

    def _process_malicious(self, stix_objects, stix_entity, results):
        if (results["classification"] == "malicious") or (
            results["classification"] == "suspicious"
        ):

            self.helper.connector_logger.info(
                f"{self.helper.connect_name}: Create STIX objects for malicious sample results!"
            )

            # Create indicators based on result
            self._create_indicators(results)

            # Create Malware and add relationship to artifact
            self._generate_stix_malware(results)

            # Create Stix Bundle and send it to OpenCTI
            bundle = self._generate_stix_bundle(stix_objects, stix_entity)
            bundles_sent = self.helper.send_stix2_bundle(bundle)

            self.helper.connector_logger.info(
                f"{self.helper.connect_name}: Number of stix bundles sent for workers: {str(len(bundles_sent))}"
            )

    def _process_message(self, data: Dict):
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        self.helper.connector_logger.info(
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

            # Integrate file analysis results with OpenCTI
            if "results" in analysis_result:
                results = self._process_file_analysis_result(
                    stix_objects, stix_entity, opencti_entity, analysis_result
                )
                self._process_malicious(stix_objects, stix_entity, results)

        elif opencti_type == "Url":
            url_sample = stix_entity["value"]
            self.helper.connector_logger.info(
                f"{self.helper.connect_name}: Submit URL sample for analysis on Spectra Analyze!"
            )

            self._url_report_flow(
                stix_entity=stix_entity,
                opencti_entity=opencti_entity,
                url_sample=url_sample,
            )

            # Submit URL sample for analysis on Spectra Analyze
            analysis_result = self._submit_url_for_analysis(
                stix_entity,
                opencti_entity,
                url_sample,
            )

            # Get file classification
            analysis_result = self._submit_file_for_classification(
                stix_entity, opencti_entity, hash
            )

            if not analysis_result:
                self.helper.connector_logger.info(
                    f"{self.helper.connect_name}: There is no analysis result for provided sample!"
                )

            # Integrate classification analysis results with OpenCTI
            if "results" not in analysis_result:

                results = self._process_file_classification_results(
                    stix_objects, stix_entity, opencti_entity, analysis_result
                )

                self._process_malicious(stix_objects, stix_entity, results)

            if not analysis_result:
                raise ValueError(
                    f"{self.helper.connect_name}: Provided sample does not exist on the appliance. Try to upload it first and re-run!"
                )

            # Integrate analysis results with OpenCTI
            results = self._process_url_analysis_result(
                stix_objects, stix_entity, opencti_entity, analysis_result
            )

            self._process_malicious(stix_objects, stix_entity, results)

        elif opencti_type == "IPv4-Addr":
            ip_sample = stix_entity["value"]
            self.helper.connector_logger.info(
                f"{self.helper.connect_name}: Starting IPv4 sample analysis on Spectra Analyze! Sample value: {str(ip_sample)}"
            )

            self._ip_report_flow(
                stix_entity=stix_entity,
                opencti_entity=opencti_entity,
                ip_sample=ip_sample,
            )

        elif opencti_type == "Domain-Name":
            domain_sample = stix_entity["value"]
            self.helper.connector_logger.info(
                f"{self.helper.connect_name}: Starting Domain sample analysis on Spectra Analyze! Sample value: {str(domain_sample)}"
            )

            self._domain_analysis_flow(
                stix_entity=stix_entity,
                opencti_entity=opencti_entity,
                domain_sample=domain_sample,
            )

        else:
            raise ValueError(
                f"{self.helper.connect_name}: Connector is not registered to work with provided {str(opencti_type)} type!"
            )


if __name__ == "__main__":
    connector = ReversingLabsSpectraAnalyzeConnector()
    connector.start()
