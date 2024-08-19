import os
import textwrap
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
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from ReversingLabs.SDK.ticloud import DynamicAnalysis, FileReputation, FileUpload

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
SLEEP_INTERVAL = 250


class ReversingLabsSpectraIntelConnector(InternalEnrichmentConnector):

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
        self.reversinglabs_spectra_intelligence_url = os.environ.get(
            "REVERSINGLABS_SPECTRA_INTELLIGENCE_URL", None
        )
        self.reversinglabs_spectra_intelligence_username = os.environ.get(
            "REVERSINGLABS_SPECTRA_INTELLIGENCE_USERNAME", None
        )
        self.reversinglabs_spectra_intelligence_password = os.environ.get(
            "REVERSINGLABS_SPECTRA_INTELLIGENCE_PASSWORD", None
        )
        self.reversinglabs_spectra_intelligence_max_tlp = os.environ.get(
            "REVERSINGLABS_MAX_TLP", None
        )
        self.reversinglabs_sandbox_platform = os.environ.get("REVERSINGLABS_SANDBOX_OS")
        self.reversinglabs_sandbox_internet_sim = os.environ.get(
            "REVERSINGLABS_SANDBOX_INTERNET_SIM"
        )
        self.reversinglabs_create_indicators = os.environ.get(
            "REVERSINGLABS_CREATE_INDICATORS"
        )
        self.reversinglabs_poll_interval = os.environ.get("REVERSINGLABS_POLL_INTERVAL")

        # Set minimum sleep interval on 250 seconds
        if SLEEP_INTERVAL > int(self.reversinglabs_poll_interval):
            self.reversinglabs_poll_interval = SLEEP_INTERVAL

        self.reversinglabs_spectra_intelligence_user_agent = (
            "ReversingLabs Spectra Intelligence File Submission OpenCTI v1.0.0"
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
                tlp, self.reversinglabs_spectra_intelligence_max_tlp
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
            f"{self.helper.connect_name} Number of Stix bundles to be enriched: {len(uniq_bundles_objects)}"
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

        # Generate Relationship Indicator -> Based on -> Observable
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

    def _generate_stix_malware(self, results):
        stix_malware_with_relationship = []
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

        malwares = results["threat_names"]
        for mal in malwares:
            if not ((mal["threat_name"] == "Unknown") or (mal["threat_name"] == "")):
                # Create Malware
                stix_malware = stix2.Malware(
                    id=Malware.generate_id(mal["threat_name"]),
                    created=now,
                    name=mal["threat_name"],
                    description="ReversingLabs",
                    is_family="false",
                    created_by_ref=self.reversinglabs_identity["standard_id"],
                )
                self.stix_objects.append(stix_malware)
                stix_malware_with_relationship.append(stix_malware)

                # Generate Relationship : observable -> "related-to" -> Malware
                observable_to_malware = self._generate_stix_relationship(
                    self.stix_entity["id"], "related-to", stix_malware.id
                )
                self.stix_objects.append(observable_to_malware)
                stix_malware_with_relationship.append(observable_to_malware)

    def _generate_stix_note(self, results):
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        classification = results["classification"]
        platform = results["platform"]
        configuration = results["configuration"]
        analysis_id = results["analysis_id"]
        analysis_time = results["analysis_time"]
        analysis_duration = results["analysis_duration"]

        abstract = "ReversingLabs Spectra Sandbox Results"
        analysis_content = textwrap.dedent(
            f"""
        # ReversingLabs Spectra Sandbox Analysis metadata
        
        Classification: **{classification}**

        | Metadata            |                 |
        | ------------------- | --------------- |
        | Analysis ID         | {analysis_id}   |
        | Analysis Time       | {analysis_time} |
        | Analysis Duration   | {analysis_duration} sec |

        ## Configuration

        Analysis is executed on **{platform}** operating system with following configuration: **{configuration}**

        """
        )

        signature_text_header = """
        
        ## Extracted signatures

        """

        signature_text_content = textwrap.dedent(
            """\
        | Description     | Risk Factor       |
        |-----------------|-------------------|
        """
        )
        signatures_list = results["signatures"]
        sorted_signatures = sorted(
            signatures_list, key=lambda x: x["risk_factor"], reverse=True
        )

        for sig in sorted_signatures:
            sig_description = sig["description"]
            sig_risk_factor = sig["risk_factor"]
            signature_text_content += textwrap.dedent(
                f"""\
            | {sig_description} | {sig_risk_factor} |
            """
            )

        signature_text_header = textwrap.dedent(signature_text_header)
        signature_text = signature_text_header + signature_text_content
        signature_content = textwrap.dedent(signature_text)
        content = analysis_content + signature_content

        # Create Note
        stix_note = stix2.Note(
            id=Note.generate_id(now, content),
            abstract=abstract,
            content=content,
            created_by_ref=self.reversinglabs_identity["standard_id"],
            object_refs=[self.stix_entity["id"]],
            object_marking_refs=[stix2.TLP_AMBER],
            custom_properties={"note_types": ["external"]},
        )
        self.stix_objects.append(stix_note)

    # TCA-0101
    def _file_reputation(self, hash):
        file_reputation = FileReputation(
            host=self.reversinglabs_spectra_intelligence_url,
            username=self.reversinglabs_spectra_intelligence_username,
            password=self.reversinglabs_spectra_intelligence_password,
            user_agent=self.reversinglabs_spectra_intelligence_user_agent,
        )
        response = file_reputation.get_file_reputation(hash)
        rl_response = response.json()
        return rl_response

    def _add_external_reference(
        self, source_name, external_reference_url, description, external_id, entity_id
    ):
        self.helper.log_info(
            f"{self.helper.connect_name}: Adding external reference to {entity_id} with source_name: {source_name} and url: {external_reference_url}"
        )

        external_reference = self.helper.api.external_reference.create(
            source_name=source_name,
            url=external_reference_url,
            description=description,
            external_id=external_id,
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=entity_id,
            external_reference_id=external_reference["id"],
        )

    def _get_mitre_attack_report(self, results):
        self.helper.log_info(
            f"{self.helper.connect_name}: Adding external reference with Mitre ATTACK techniques and tactics"
        )

        mitre_attack = results["mitre_attack"]

        # Tactic type [Enterprise, Mobile, ICS]
        tactics_list = mitre_attack["matrix_list"][0]["tactics"]["tactic_list"]

        for tactic in tactics_list:
            tac_id = tactic["id"]
            tac_name = tactic["name"]
            tac_url = f"https://attack.mitre.org/tactics/{tac_id}"
            techniques_list = tactic["techniques"]["technique_list"]
            self._add_external_reference(
                source_name=f"Mitre-{tac_name}",
                external_reference_url=tac_url,
                entity_id=self.stix_entity["id"],
                description=tac_name,
                external_id=tac_id,
            )
            for technique in techniques_list:
                tech_id = technique["id"]
                if "." in tech_id:
                    tech_id_base, tech_id_sub = tech_id.split(".")
                    tech_url = f"https://attack.mitre.org/techniques/{tech_id_base}/{tech_id_sub}"
                else:
                    tech_url = f"https://attack.mitre.org/techniques/{tech_id}"
                tech_name = technique["name"]
                self._add_external_reference(
                    source_name=f"Mitre-{tech_name}",
                    external_reference_url=tech_url,
                    entity_id=self.stix_entity["id"],
                    description=tech_name,
                    external_id=tech_id,
                )

    def _process_dropped_files(self, results):
        dropped_files = results["dropped_files"]
        files = {}

        for file in dropped_files:
            file_classification = file["classification"]
            if file_classification == "MALICIOUS":
                main_observable_type = "File"
                file_sha1 = file["sha1"]
                file_sha256 = file["sha256"]
                file_reputation_report = self._file_reputation(file_sha1)
                files["status"] = file_reputation_report["rl"]["malware_presence"][
                    "status"
                ]
                if files["status"] == "MALICIOUS":
                    indicator_name = file["file_name"]
                    indicator_pattern = f"[file:hashes. 'SHA-256' = '{file_sha256}']"
                    files["description"] = (
                        "Observable is generated from dropped files by ReversingLabs Sandbox"
                    )
                    files["labels"] = []
                    files["labels"].append(
                        file_reputation_report["rl"]["malware_presence"][
                            "classification"
                        ]["family_name"]
                    )
                    files["labels"].append(
                        file_reputation_report["rl"]["malware_presence"][
                            "classification"
                        ]["type"]
                    )
                    files["platform"] = file_reputation_report["rl"][
                        "malware_presence"
                    ]["classification"]["platform"]
                    score = (
                        file_reputation_report["rl"]["malware_presence"]["threat_level"]
                        + file_reputation_report["rl"]["malware_presence"][
                            "trust_factor"
                        ]
                    ) * 10
                    files["score"] = self._generate_score(score)
                    relationship = "related-to"
                    self._generate_stix_indicator(
                        files,
                        indicator_name,
                        indicator_pattern,
                        main_observable_type,
                        relationship,
                    )

    def _generate_score(self, score):
        self.helper.api.stix2.put_attribute_in_extension(
            self.stix_entity, STIX_EXT_OCTI_SCO, "x_opencti_score", score, True
        )
        return score

    def _upsert_artifact(self, results):
        risk_score = results["score"] * 10
        score = self._generate_score(risk_score)
        labels = results["labels"]

        self.helper.api.stix_cyber_observable.update_field(
            id=self.stix_entity["id"],
            input={
                "key": "x_opencti_score",
                "value": score,
            },
        )

        classification = results["classification"]
        description = f"Reversinglabs Spectra Sandbox added {classification} classification to requested sample"

        self.helper.api.stix_cyber_observable.update_field(
            id=self.stix_entity["id"],
            input={
                "key": "x_opencti_description",
                "value": description,
            },
        )

        for lab in labels:
            if not ((lab == "Unknown") or (lab == "")):
                label = self.helper.api.label.create(
                    value=lab,
                    color="#d84315",
                )
                self.helper.api.stix_cyber_observable.add_label(
                    id=self.stix_entity["id"], label_id=label["id"]
                )

    def _submit_url_for_analysis(
        self, stix_entity, opencti_entity, network_location, network_type
    ):
        self.stix_entity = stix_entity
        self.network_location = [network_location]
        platform = self.reversinglabs_sandbox_platform
        url_sample = self.network_location[0]

        self.helper.log_info(
            f"{self.helper.connect_name}: Submit URL {str(url_sample)} for analysis to ReversingLabs Spectra Sandbox"
        )

        detonate_url = DynamicAnalysis(
            host=self.reversinglabs_spectra_intelligence_url,
            username=self.reversinglabs_spectra_intelligence_username,
            password=self.reversinglabs_spectra_intelligence_password,
            user_agent=self.reversinglabs_spectra_intelligence_user_agent,
        )

        try:
            response = detonate_url.detonate_url(
                url_string=url_sample, platform=platform
            )

        except Exception as err:
            self.helper.log_info(
                f"{self.helper.connect_name}: Failed to start URL analysis on ReversingLabs Spectra Sandbox"
            )
            raise ValueError(f"{str(err)}") from err

        self.helper.log_info(
            f"{self.helper.connect_name}: URL is successfully submitted for analysis on Spectra Sandbox. HTTP Status Code: {str(response.status_code)}"
        )

        rl_response = response.json()
        return rl_response

    def _upload_file_to_spectra_sandbox(self, file_uri, is_archive, sample_name):

        try:
            file_content = self.helper.api.fetch_opencti_file(file_uri, binary=True)

            submit_file = FileUpload(
                host=self.reversinglabs_spectra_intelligence_url,
                username=self.reversinglabs_spectra_intelligence_username,
                password=self.reversinglabs_spectra_intelligence_password,
                user_agent=self.reversinglabs_spectra_intelligence_user_agent,
            )

            # Submit File for analysis
            if is_archive == False:

                file = open(sample_name, "wb")
                file.write(file_content)
                file.close()

                self.helper.log_info(
                    f"{self.helper.connect_name}: Submitting artifact {str(sample_name)} to ReversingLabs Spectra Sandbox."
                )

                with open(sample_name, "rb") as file_handle:
                    response = submit_file.upload_sample_from_file(
                        file_handle=file_handle, sample_name=sample_name
                    )

            # Submit Archive for analysis
            else:
                self.helper.log_info(
                    f"{self.helper.connect_name}: Submitting archive artifact {str(sample_name)} to ReversingLabs Spectra Sandbox."
                )

                file = open(sample_name, "wb")
                file.write(file_content)
                file.close()

                archive_type = "zip"

                with open(sample_name, "rb") as file_handle:
                    response = submit_file.upload_sample_from_file(
                        file_handle=file_handle,
                        sample_name=sample_name,
                        archive_type=archive_type,
                        archive_password="infected",
                    )

            # Remove File from OS
            os.remove(sample_name)
            return response.status_code

        except Exception as err:
            raise ValueError(f"{str(err)}") from err

    def _submit_file_for_analysis(self, stix_entity, opencti_entity, hash, hash_type):
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.hash = hash
        self.hash_type = hash_type

        platform = self.reversinglabs_sandbox_platform
        internet_sim = self.reversinglabs_sandbox_internet_sim

        if internet_sim in TRUE_LIST:
            internet_sim = True
        if internet_sim in FALSE_LIST:
            internet_sim = False
        else:
            self.helper.log_info(
                "{self.helper.connect_name}: Wrong input provided in REVERSINGLABS_SANDBOX_INTERNET_SIM env variable: {str(internet_sim)}."
            )
            raise ValueError("Wrong input provided!")

        if stix_entity["x_opencti_type"] == "Artifact":
            sample_name = self.opencti_entity["importFiles"][0]["name"]
            file_id = self.opencti_entity["importFiles"][0]["id"]
            file_mime_type = self.opencti_entity["mime_type"]
            file_uri = f"{self.helper.opencti_url}/storage/get/{file_id}"

            if file_mime_type in ZIP_MIME_TYPES:
                is_archive = True
            else:
                is_archive = False

            upload_status = self._upload_file_to_spectra_sandbox(
                file_uri, is_archive, sample_name
            )

            if upload_status == 200:
                self.helper.log_info(
                    f"{self.helper.connect_name}: File is successfully submitted to RL Spectra Sandbox. Response status code is {str(upload_status)}"
                )
            else:
                self.helper.log_info(
                    f"{self.helper.connect_name}: There was an issue with file submit to RL Spectra Sandbox. Response status code is {str(upload_status)}"
                )
                raise ValueError(
                    f"{self.helper.connect_name}: Skipping Dynamic Analysis processing due to issues with file upload!"
                )
        else:
            sample_name = self.opencti_entity["observable_value"]
            file_mime_type = "None"
            is_archive = False

        # Start analysis on submitted file
        analyze_file = DynamicAnalysis(
            host=self.reversinglabs_spectra_intelligence_url,
            username=self.reversinglabs_spectra_intelligence_username,
            password=self.reversinglabs_spectra_intelligence_password,
            user_agent=self.reversinglabs_spectra_intelligence_user_agent,
        )

        try:
            response = analyze_file.detonate_sample(
                sample_hash=self.hash,
                platform=platform,
                is_archive=is_archive,
                internet_simulation=internet_sim,
            )
        except Exception as err:
            self.helper.log_info(
                f"{self.helper.connect_name}: Failed to start artifact analysis on ReversingLabs Spectra Sandbox"
            )
            raise ValueError(f"{str(err)}") from err

        rl_response = response.json()
        # Add info about archive type to use for fetching from TCA-0106
        rl_response["rl"]["is_archive"] = str(is_archive)
        return rl_response

    def _fetch_analysis_result(self, stix_entity, opencti_entity, analysis_status):
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.analysis_status = analysis_status

        try:
            sample_hash = analysis_status["rl"]["requested_hash"]
            is_archive = analysis_status["rl"]["is_archive"]
            sample_url = ""
            sample_type = "File"
        except:
            sample_hash = analysis_status["rl"]["sha1"]
            is_archive = ""
            sample_url = analysis_status["rl"]["url"]
            sample_type = "Url"

        self.helper.log_info(
            f"{self.helper.connect_name}: Submission status {str(self.analysis_status)}"
        )

        if is_archive == "False":
            # Parse output for regular file
            analysis_id = analysis_status["rl"]["analysis_id"]
            is_archive = False
        elif is_archive == "True":
            # Parse output for zip file
            try:
                analysis_id = analysis_status["rl"]["files"][0]["analysis_id"]
            except Exception as err:
                analysis_error = analysis_status["rl"]["files"][0]["error_message"]
                raise ValueError(
                    f"{self.helper.connect_name}: ERROR: {str(analysis_error)}"
                ) from err
            sample_hash = analysis_status["rl"]["files"][0]["sha1"]
            is_archive = True
        else:
            # Parse output for url sample
            analysis_id = analysis_status["rl"]["analysis_id"]
            is_archive = ""

        # Start analysis on submitted file
        dynamic_analysis = DynamicAnalysis(
            host=self.reversinglabs_spectra_intelligence_url,
            username=self.reversinglabs_spectra_intelligence_username,
            password=self.reversinglabs_spectra_intelligence_password,
            user_agent=self.reversinglabs_spectra_intelligence_user_agent,
        )

        for retry in range(0, 5):
            self.helper.log_info(
                f"{self.helper.connect_name}: Check if report is ready on Reversinglabs Spectra Intelligence."
            )

            if sample_type == "File":
                try:
                    analysis_result = dynamic_analysis.get_dynamic_analysis_results(
                        sample_hash=sample_hash,
                        is_archive=is_archive,
                        analysis_id=analysis_id,
                    )

                    rl_response = analysis_result.json()
                    rl_response["rl"]["sample_name"] = str(sample_hash)
                    return rl_response

                except Exception as err:
                    self.helper.log_info(
                        f"{self.helper.connect_name}: Failed to fetch report status from ReversingLabs Spectra Intelligence. Error: {str(err)}"
                    )
                    self.helper.log_info(
                        f"{self.helper.connect_name}: Wait for {str(self.reversinglabs_poll_interval)} seconds and retry."
                    )
                    time.sleep(int(self.reversinglabs_poll_interval))
            else:
                try:
                    analysis_result = dynamic_analysis.get_dynamic_analysis_results(
                        # url=sample_url,
                        url_sha1=sample_hash,
                        analysis_id=analysis_id,
                    )

                    rl_response = analysis_result.json()
                    rl_response["rl"]["sample_name"] = str(sample_url)
                    return rl_response

                except Exception as err:
                    self.helper.log_info(
                        f"{self.helper.connect_name}: Failed to fetch report status from ReversingLabs Spectra Intelligence. Error: {str(err)}"
                    )
                    self.helper.log_info(
                        f"{self.helper.connect_name}: Wait for {str(self.reversinglabs_poll_interval)} seconds and retry."
                    )
                    time.sleep(int(self.reversinglabs_poll_interval))

    def _process_analysis_result(
        self, stix_objects, stix_entity, opencti_entity, analysis_result
    ):
        self.stix_objects = stix_objects
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.analysis_result = analysis_result

        results = {}
        try:
            results["requested_hash"] = self.analysis_result["rl"]["requested_hash"]
        except:
            try:
                results["requested_hash"] = self.analysis_result["rl"][
                    "requested_sha1_url"
                ]
            except Exception as err:
                raise ValueError(
                    f"{self.helper.connect_name}: INFO: Fetching analysis result took more than expected! Please try again shortly!"
                ) from err
        results["sample_name"] = self.analysis_result["rl"]["sample_name"]
        results["classification"] = self.analysis_result["rl"]["report"][
            "classification"
        ]
        results["score"] = self.analysis_result["rl"]["report"]["risk_score"]
        results["sha256"] = self.analysis_result["rl"]["report"]["sha256"]
        results["platform"] = self.analysis_result["rl"]["report"]["platform"]
        results["configuration"] = self.analysis_result["rl"]["report"]["configuration"]
        results["analysis_id"] = self.analysis_result["rl"]["report"]["analysis_id"]
        results["analysis_time"] = self.analysis_result["rl"]["report"]["analysis_time"]
        results["analysis_duration"] = self.analysis_result["rl"]["report"][
            "analysis_duration"
        ]
        results["description"] = (
            "Created from report received by ReversingLabs Spectra Sandbox"
        )
        results["threat_names"] = self.analysis_result["rl"]["report"]["threat_names"]
        results["signatures"] = self.analysis_result["rl"]["report"]["signatures"]
        results["labels"] = []

        # Creating labels in OpenCTI out of threat_names in report
        for threat in results["threat_names"]:
            results["labels"].append(threat["threat_name"])

        # Add classification status to OpenCTI label
        results["labels"].append(results["classification"])

        # Add score and description to the Artifact
        self._upsert_artifact(results)

        if "screenshots" in self.analysis_result["rl"]["report"]:
            results["screenshots"] = self.analysis_result["rl"]["report"]["screenshots"]
            # Add external reference to Artifact Screenshots
            self._add_external_reference(
                source_name="ReversingLabs-Link-To-Screenshots",
                external_reference_url=results["screenshots"],
                entity_id=self.stix_entity["id"],
                description="This link is generated when the report is requested, and expires in 1 hour.",
                external_id="",
            )

        if "dropped_files_url" in self.analysis_result["rl"]["report"]:
            results["dropped_files_url"] = self.analysis_result["rl"]["report"][
                "dropped_files_url"
            ]
            # Add external reference to Artifact Dropped Files
            self._add_external_reference(
                source_name="ReversingLabs-Link-To-Dropped-Files",
                external_reference_url=results["dropped_files_url"],
                entity_id=self.stix_entity["id"],
                description="This link is generated when the report is requested, and expires in 1 hour.",
                external_id="",
            )

        if "memory_strings" in self.analysis_result["rl"]["report"]:
            results["memory_strings"] = self.analysis_result["rl"]["report"][
                "memory_strings"
            ]
            # Add external reference to Artifact Memory Strings
            self._add_external_reference(
                source_name="ReversingLabs-Link-To-Memory-Strings",
                external_reference_url=results["memory_strings"],
                entity_id=self.stix_entity["id"],
                description="This link is generated when the report is requested, and expires in 1 hour.",
                external_id="",
            )

        if "pcap" in self.analysis_result["rl"]["report"]:
            results["pcap"] = self.analysis_result["rl"]["report"]["pcap"]
            # Add external reference to Artifact Pcap
            self._add_external_reference(
                source_name="ReversingLabs-Link-To-Pcap",
                external_reference_url=results["pcap"],
                entity_id=self.stix_entity["id"],
                description="This link is generated when the report is requested, and expires in 1 hour.",
                external_id="",
            )

        if "mitre_attack" in self.analysis_result["rl"]["report"]:
            results["mitre_attack"] = self.analysis_result["rl"]["report"][
                "mitre_attack"
            ]
            # Add external reference to Artifact MITRE_ATTACK
            self._get_mitre_attack_report(results)

        # Create indicator based on the CLASSIFICATION result
        if (results["classification"] == "MALICIOUS") or (
            results["classification"] == "SUSPICIOUS"
        ):
            self.helper.log_info(
                f"{self.helper.connect_name}: Generating indicators based on the classification"
            )
            if self.stix_entity["x_opencti_type"] == "Artifact":
                indicator_sha256 = results["sha256"]
                indicator_name = results["sample_name"]
                indicator_pattern = f"[file:hashes. 'SHA-256' = '{indicator_sha256}']"
                main_observable_type = "File"
                relationship = "based-on"
            elif self.stix_entity["x_opencti_type"] == "StixFile":
                indicator_sha256 = results["sha256"]
                indicator_name = results["sha256"]
                indicator_pattern = f"[file:hashes. 'SHA-256' = '{indicator_sha256}']"
                main_observable_type = "File"
                relationship = "based-on"
            elif self.stix_entity["x_opencti_type"] == "Url":
                indicator_name = results["sample_name"]
                indicator_pattern = f"[url:value  = '{indicator_name}']"
                main_observable_type = "Url"
                relationship = "based-on"
            else:
                self.helper.log_info(
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

            # Create Malware and add relationship to observable
            self._generate_stix_malware(results)

            # Create Note and add relationship to observable
            self._generate_stix_note(results)

            if "dropped_files" in self.analysis_result["rl"]["report"]:
                results["dropped_files"] = self.analysis_result["rl"]["report"][
                    "dropped_files"
                ]
                # Process Dropped Files
                self._process_dropped_files(results)

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

        if opencti_type in FILE_SAMPLE:
            # Extract hash type and value from Entity {[md5], [sha1], [sha256]}
            hashes = opencti_entity.get("hashes")
            for ent_hash in hashes:
                if not (
                    (ent_hash["algorithm"] == "MD5")
                    or (ent_hash["algorithm"] == "SHA-512")
                ):
                    hash = ent_hash["hash"]
                    hash_type = ent_hash["algorithm"]

            # Submit File sample for analysis
            analysis_status = self._submit_file_for_analysis(
                stix_entity,
                opencti_entity,
                hash,
                hash_type,
            )

            analysis_result = self._fetch_analysis_result(
                stix_entity,
                opencti_entity,
                analysis_status,
            )

            # Integrate analysis result with OpenCTI
            self._process_analysis_result(
                stix_objects, stix_entity, opencti_entity, analysis_result
            )

            # Create the bundle and send it to OpenCTI.
            bundle = self._generate_stix_bundle(stix_objects, stix_entity)
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            self.helper.log_info(
                f"{self.helper.connect_name}: Number of stix bundles sent for workers: {str(len(bundles_sent))}"
            )

        elif opencti_type == "Url":
            network_location = stix_entity["value"]
            network_type = stix_entity["type"]

            # Submit URL sample for analysis (url, ip, domain)
            analysis_status = self._submit_url_for_analysis(
                stix_entity,
                opencti_entity,
                network_location,
                network_type,
            )

            analysis_result = self._fetch_analysis_result(
                stix_entity,
                opencti_entity,
                analysis_status,
            )

            # Integrate analysis result with OpenCTI
            self._process_analysis_result(
                stix_objects, stix_entity, opencti_entity, analysis_result
            )

            # Create the bundle and send it to OpenCTI.
            bundle = self._generate_stix_bundle(stix_objects, stix_entity)
            bundles_sent = self.helper.send_stix2_bundle(bundle)

            self.helper.log_info(
                f"{self.helper.connect_name}: Number of stix bundles sent for workers: {str(len(bundles_sent))}"
            )

        else:
            self.helper.log_info(
                f"{self.helper.connect_name}: Connector is not configured for data type: {opencti_type}"
            )
            return


if __name__ == "__main__":
    connector = ReversingLabsSpectraIntelConnector()
    connector.start()
