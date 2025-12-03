import ipaddress
import json
import os
import time
from io import BytesIO
from typing import Dict

import jbxapi
import pycti
import stix2
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper, StixCoreRelationship


class JoeSandboxConnector:

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.identity = self.helper.api.identity.create(
            type="Organization", name="Joe Security", description="Joe Security"
        )["standard_id"]
        self.octi_api_url = self.config.opencti.url
        self.joe_sandbox_client = jbxapi.JoeSandbox(
            apikey=self.config.joe_sandbox.api_key.get_secret_value(),
            apiurl=self.config.joe_sandbox.api_url,
            accept_tac=self.config.joe_sandbox.accept_tac,
            timeout=self.config.joe_sandbox.api_timeout,
            verify_ssl=self.config.joe_sandbox.verify_ssl,
            retries=self.config.joe_sandbox.api_retries,
            proxies=self.config.joe_sandbox.proxies,
            user_agent=self.config.joe_sandbox.user_agent,
        )
        self._report_types = self.config.joe_sandbox.report_types.split(",")
        self._systems = self.config.joe_sandbox.systems.split(",")
        self._analysis_time = self.config.joe_sandbox.analysis_time
        self._internet_access = self.config.joe_sandbox.internet_access
        self._internet_simulation = self.config.joe_sandbox.internet_simulation
        self._hybrid_code_analysis = self.config.joe_sandbox.hybrid_code_analysis
        self._hybrid_decompilation = self.config.joe_sandbox.hybrid_decompilation
        self._report_cache = self.config.joe_sandbox.report_cache
        self._apk_instrumentation = self.config.joe_sandbox.apk_instrumentation
        self._amsi_unpacking = self.config.joe_sandbox.amsi_unpacking
        self._ssl_inspection = self.config.joe_sandbox.ssl_inspection
        self._vba_instrumentation = self.config.joe_sandbox.vba_instrumentation
        self._js_instrumentation = self.config.joe_sandbox.js_instrumentation
        self._java_jar_tracing = self.config.joe_sandbox.java_jar_tracing
        self._dotnet_tracing = self.config.joe_sandbox.dotnet_tracing
        self._start_as_normal_user = self.config.joe_sandbox.start_as_normal_user
        self._system_date = self.config.joe_sandbox.system_date
        self._language_and_locale = self.config.joe_sandbox.language_and_locale
        self._localized_internet_country = (
            self.config.joe_sandbox.localized_internet_country
        )
        self._email_notification = self.config.joe_sandbox.email_notification
        self._archive_no_unpack = self.config.joe_sandbox.archive_no_unpack
        self._hypervisor_based_inspection = (
            self.config.joe_sandbox.hypervisor_based_inspection
        )
        self._fast_mode = self.config.joe_sandbox.fast_mode
        self._secondary_results = self.config.joe_sandbox.secondary_results
        self._cookbook = None
        if self.config.joe_sandbox.cookbook_file_path and os.path.exists(
            self.config.joe_sandbox.cookbook_file_path
        ):
            with open(self.config.joe_sandbox.cookbook_file_path, "rb") as f:
                self._cookbook = BytesIO(f.read())
        self._document_password = (
            self.config.joe_sandbox.document_password.get_secret_value()
        )
        self._archive_password = (
            self.config.joe_sandbox.archive_password.get_secret_value()
        )
        self._command_line_argument = self.config.joe_sandbox.command_line_argument
        self._encrypt_with_password = (
            self.config.joe_sandbox.encrypt_with_password.get_secret_value()
            if self.config.joe_sandbox.encrypt_with_password
            else None
        )
        self._browser = self.config.joe_sandbox.browser
        self._url_reputation = self.config.joe_sandbox.url_reputation
        self._export_to_jbxview = self.config.joe_sandbox.export_to_jbxview
        self._delete_after_days = self.config.joe_sandbox.delete_after_days
        self._priority = self.config.joe_sandbox.priority
        self._default_tlp = self.config.joe_sandbox.default_tlp.lower()
        self._yara_color = self.config.joe_sandbox.yara_color
        default_color = self.config.joe_sandbox.default_color
        self.helper.api.label.create(value="dynamic", color=default_color)

    def _process_observable(self, observable):
        params = {
            # JOE SANDBOX DEFAULT PARAMETERS, see https://github.com/joesecurity/jbxapi/blob/master/jbxapi.py
            # See https://jbxcloud.joesecurity.org/#windows for all the available systems
            "systems": self._systems,  # Use this parameter multiple times to select more than one system.
            "analysis-time": self._analysis_time,  # Set the analysis time in seconds.
            "document-password": self._document_password,  # Password for decrypting documents like MS Office and PDFs
            "archive-password": self._archive_password,  # This password will be used to decrypt archives (zip, 7z, rar etc.).
            "command-line-argument": self._command_line_argument,  # Will start the sample with the given command-line argument. Currently only available on Windows analyzers.
            "localized-internet-country": self._localized_internet_country,  # Select the country to use for routing internet access through.
            "internet-access": self._internet_access,  # Enable full internet access.
            "internet-simulation": self._internet_simulation,  # Enable internet simulation. internet-access must be explicitly set to false for this option to work.
            "report-cache": self._report_cache,  # Enable the report cache. Check the cache for existing reports before running a full analysis.
            "hybrid-code-analysis": self._hybrid_code_analysis,  # Enable Hybrid Code Analysis (HCA).
            "hybrid-decompilation": self._hybrid_decompilation,  # Enable Hybrid Decompilation (DEC).
            "ssl-inspection": self._ssl_inspection,  # Enable HTTPS inspection.
            "vba-instrumentation": self._vba_instrumentation,  # Enable VBA instrumentation (two analyses are performed)
            "js-instrumentation": self._js_instrumentation,  # Enable Javascript instrumentation (two analyses are performed)
            "java-jar-tracing": self._java_jar_tracing,  # Enable JAVA JAR tracing (two analyses are performed)
            "dotnet-tracing": self._dotnet_tracing,  # Enable .NET tracing (two analyses are performed)
            "email-notification": self._email_notification,  # Send an email notification once the analysis completes.
            "start-as-normal-user": self._start_as_normal_user,  # Starts the Sample with normal user privileges
            "system-date": self._system_date,  # Change the analyzer’s system date (helpful for date-aware samples), format is: YYYY-MM-DD
            "language-and-locale": self._language_and_locale,  # Changes the language and locale of the analysis machine
            "archive-no-unpack": self._archive_no_unpack,  # Do not unpack archives (zip, 7z etc) containing multiple files.
            "hypervisor-based-inspection": self._hypervisor_based_inspection,  # Enable Hypervisor based Inspection
            "fast-mode": self._fast_mode,  # Fast Mode focuses on fast analysis and detection versus deep forensic analysis.
            "secondary-results": self._secondary_results,  # Enables secondary results such as Yara rule generation, classification via Joe Sandbox Class as well as several detail reports. Analysis will run faster with disabled secondary results
            "apk-instrumentation": self._apk_instrumentation,  # Perform APK DEX code instrumentation.
            "amsi-unpacking": self._amsi_unpacking,  # Perform generic unpacking using the Microsoft Antimalware Scan Interface (AMSI).
            "encrypt-with-password": self._encrypt_with_password,  # Encryption password for analyses
            # JOE SANDBOX CLOUD EXCLUSIVE PARAMETERS - Only include these if they are defined
            **(
                {"url-reputation": self._url_reputation} if self._url_reputation else {}
            ),
            **(
                {"export-to-jbxview": self._export_to_jbxview}
                if self._export_to_jbxview
                else {}
            ),
            **(
                {"delete-after-days": self._delete_after_days}
                if self._delete_after_days
                else {}
            ),
            "priority": self._priority,
        }
        submission_dict = {}
        if observable["entity_type"] == "Url":
            self.helper.log_info(
                f"Submitting {observable['observable_value']} to JoeSandbox for analysis..."
            )
            if self._browser:
                submission_dict = self.joe_sandbox_client.submit_url(
                    url=observable["observable_value"], params=params
                )
            else:
                submission_dict = self.joe_sandbox_client.submit_sample_url(
                    url=observable["observable_value"], params=params
                )
        elif observable["entity_type"] == "Artifact":
            sample = self._download_artifact(observable)
            self.helper.log_info(
                f"Submitting {observable['importFiles'][0]['name']} to JoeSandbox for analysis..."
            )
            submission_dict = self.joe_sandbox_client.submit_sample(
                sample, cookbook=self._cookbook, params=params
            )
        else:
            raise ValueError(
                f"Failed to process observable, {observable['entity_type']} is not a supported entity type."
            )
        self.helper.log_info(json.dumps(submission_dict, indent=2))
        submission_id = submission_dict["submission_id"]
        return self._process_submission(observable, submission_id)

    def _download_artifact(self, observable):
        """
        Download Artifact from OpenCTI
        """
        file_name = observable["importFiles"][0]["name"]
        file_id = observable["importFiles"][0]["id"]
        file_uri = f"{self.octi_api_url}/storage/get/{file_id}"
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)
        artifact = BytesIO(file_content)
        artifact.name = file_name
        return artifact

    def _process_submission(self, observable, submission_id):
        """
        observable: The dict containing the observable to enrich
        submission_id: Int representing the submission id
        returns: a str representing a message to return to OpenCTI
        """
        submission_dict = self._wait_for_analyses(submission_id)
        self.helper.log_info(json.dumps(submission_dict, indent=2))
        bundle_objects = self._process_analyses(
            observable, submission_dict.get("analyses")
        )
        score = submission_dict.get("most_relevant_analysis").get("score")
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"], input={"key": "x_opencti_score", "value": str(score)}
        )
        if bundle_objects:
            bundle = self.helper.stix2_create_bundle(bundle_objects)
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        else:
            return "Nothing to attach"

    def _wait_for_analyses(self, submission_id):
        """
        Wait for submission to finish and return the analyses.

        submission_id: An int representing the submission to wait for.
        returns: Submission dict, see https://jbxcloud.joesecurity.org/userguide?sphinxurl=usage%2Fwebapi.html#id3
        """
        while True:
            time.sleep(1)
            submission_info = self.joe_sandbox_client.submission_info(submission_id)
            if submission_info["status"] != "finished":
                continue
            return submission_info

    def _process_analyses(self, observable, analyses):
        """
        Process all analyses and create observables/relationships
        See https://jbxcloud.joesecurity.org/userguide?sphinxurl=usage%2Fwebapi.html#id8
        for all the report types

        analyses: a list of dicts containing the analysis info
        """
        bundle_objects = []
        for analysis_dict in analyses:
            webid = analysis_dict["webid"]
            threatname = analysis_dict["threatname"]
            detection = analysis_dict["detection"]
            analysis_url = f"{self.config.joe_sandbox.analysis_url}/{webid}"
            external_reference = self.helper.api.external_reference.create(
                source_name=f"Joe Sandbox Analysis [{detection}-{threatname}-{webid}]",
                url=analysis_url,
                description=f"Joe Sandbox Analysis, Web ID: {webid}",
            )
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=observable["id"], external_reference_id=external_reference["id"]
            )
            if "executive" in self._report_types:
                try:
                    name, executive_report = self.joe_sandbox_client.analysis_download(
                        webid, "executive", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=executive_report,
                        mime_type="text/html",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve html report, exception: {e}"
                    )
            if "html" in self._report_types:
                try:
                    name, html_report = self.joe_sandbox_client.analysis_download(
                        webid, "html", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=html_report,
                        mime_type="text/html",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve html report, exception: {e}"
                    )
            if "iochtml" in self._report_types:
                try:
                    name, iochtml_report = self.joe_sandbox_client.analysis_download(
                        webid, "iochtml", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=iochtml_report,
                        mime_type="text/html",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve iochtml report, exception: {e}"
                    )
            if "iocxml" in self._report_types:
                try:
                    name, iocxml = self.joe_sandbox_client.analysis_download(
                        webid, "iocxml", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=iocxml,
                        mime_type="application/xml",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve iocxml report, exception: {e}"
                    )
            if "iocjson" in self._report_types:
                try:
                    name, iocjson = self.joe_sandbox_client.analysis_download(
                        webid, "iocjson", password=self._encrypt_with_password
                    )
                    iocjson = json.loads(iocjson)
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=json.dumps(iocjson, indent=2),
                        mime_type="application/json",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve iocjson report, exception: {e}"
                    )
            if "json" in self._report_types:
                try:
                    name, json_report = self.joe_sandbox_client.analysis_download(
                        webid, "json", password=self._encrypt_with_password
                    )
                    bundle_objects = self._process_json_report(
                        self, observable, json_report
                    )
                    json_report = json.loads(json_report)
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=json.dumps(json_report, indent=2),
                        mime_type="application/json",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve json report, exception: {e}"
                    )
            if "lightjsonfixed" in self._report_types:
                try:
                    name, json_report = self.joe_sandbox_client.analysis_download(
                        webid, "lightjsonfixed", password=self._encrypt_with_password
                    )
                    bundle_objects = self._process_json_report(
                        self, observable, json_report
                    )
                    json_report = json.loads(json_report)
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=json.dumps(json_report, indent=2),
                        mime_type="application/json",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve lightjsonfixed report, exception: {e}"
                    )
            if "xml" in self._report_types:
                try:
                    name, xml = self.joe_sandbox_client.analysis_download(
                        webid, "xml", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=xml,
                        mime_type="application/xml",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve xml report, exception: {e}"
                    )
            if "lightxml" in self._report_types:
                try:
                    name, lightxml = self.joe_sandbox_client.analysis_download(
                        webid, "lightxml", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=lightxml,
                        mime_type="application/xml",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve lightxml report, exception: {e}"
                    )
            if "unpackpe" in self._report_types:
                try:
                    name, unpackpe = self.joe_sandbox_client.analysis_download(
                        webid, "unpackpe", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=unpackpe,
                        mime_type="application/zip",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve unpackpe zip, exception: {e}"
                    )
            if "stix" in self._report_types:
                try:
                    name, stix_report = self.joe_sandbox_client.analysis_download(
                        webid, "stix", password=self._encrypt_with_password
                    )
                    stix_report = json.loads(stix_report)
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=json.dumps(stix_report, indent=2),
                        mime_type="application/json",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve stix report, exception: {e}"
                    )
            if "ida" in self._report_types:
                try:
                    name, ida = self.joe_sandbox_client.analysis_download(
                        webid, "ida", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=ida,
                        mime_type="application/zip",
                    )
                except Exception as e:
                    self.helper.log_info(f"Failed to retrieve ida zip, exception: {e}")
            if "misp" in self._report_types:
                try:
                    name, misp = self.joe_sandbox_client.analysis_download(
                        webid, "misp", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=misp,
                        mime_type="application/xml",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve misp report, exception: {e}"
                    )
            if "pdf" in self._report_types:
                try:
                    name, pdf = self.joe_sandbox_client.analysis_download(
                        webid, "pdf", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=pdf,
                        mime_type="application/pdf",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve pdf report, exception: {e}"
                    )
            if "pdfexecutive" in self._report_types:
                try:
                    name, pdfexecutive = self.joe_sandbox_client.analysis_download(
                        webid, "pdfexecutive", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=pdfexecutive,
                        mime_type="application/pdf",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve pdf management (pdfexecutive) report, exception: {e}"
                    )
            if "pcap" in self._report_types:
                try:
                    name, pcap = self.joe_sandbox_client.analysis_download(
                        webid, "pcap", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=pcap,
                        mime_type="application/vnd.tcpdump.pcap",
                    )
                except Exception as e:
                    self.helper.log_info(f"Failed to retrieve pcap, exception: {e}")
            if "pcapsslinspection" in self._report_types:
                try:
                    name, pcapsslinspection = self.joe_sandbox_client.analysis_download(
                        webid, "pcapsslinspection", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=pcapsslinspection,
                        mime_type="application/vnd.tcpdump.pcap",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve pcapsslinspection, exception: {e}"
                    )
            if "pcapunified" in self._report_types:
                try:
                    name, pcapunified = self.joe_sandbox_client.analysis_download(
                        webid, "pcapunified", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=pcapunified,
                        mime_type="application/vnd.tcpdump.pcap",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve pcapunified, exception: {e}"
                    )
            if "maec" in self._report_types:
                try:
                    name, maec = self.joe_sandbox_client.analysis_download(
                        webid, "maec", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=maec,
                        mime_type="application/xml",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve maec report, exception: {e}"
                    )
            if "memdumps" in self._report_types:
                try:
                    name, memdumps = self.joe_sandbox_client.analysis_download(
                        webid, "memdumps", password=self._encrypt_with_password
                    )
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=name,
                        data=memdumps,
                        mime_type="application/zip",
                    )
                except Exception as e:
                    self.helper.log_info(
                        f"Failed to retrieve memdumps zip, exception: {e}"
                    )
        return bundle_objects

    def _process_json(self, observable, json_report):
        """
        Handle the json report
        """
        bundle_objects = []
        json_report = json_report.get("analysis")
        malware_configs = json_report.get("malware_configs")
        if malware_configs:
            configs = malware_configs.get("config")
            for config_dict in configs:
                note_content = f"```\n{json.dumps(config_dict, indent=2)}\n```"
                note = stix2.Note(
                    id=pycti.Note.generate_id(None, note_content),
                    abstract=f"Malware Configuration ({config_dict['@threatname']})",
                    content=note_content,
                    created_by_ref=self.identity,
                    object_marking_refs=[self._default_tlp],
                    object_refs=[observable["standard_id"]],
                )
                bundle_objects.append(note)
        yara = json_report.get("yara")
        if yara:
            memorydumps = yara.get("memorydumps")
            if memorydumps:
                for hit in memorydumps["hit"]:
                    label = self.helper.api.label.create(
                        value=hit["rule"], color=self._yara_color
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=observable["id"], label_id=label["id"]
                    )
            unpackedpes = yara.get("unpackedpes")
            if unpackedpes:
                for hit in unpackedpes["hit"]:
                    label = self.helper.api.label.create(
                        value=hit["rule"], color=self._yara_color
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=observable["id"], label_id=label["id"]
                    )
        domaininfo = json_report.get("domaininfo")
        if domaininfo:
            for domain_dict in domaininfo.get("domain"):
                domain_stix = stix2.DomainName(
                    value=domain_dict["@name"],
                    object_marking_refs=[self._default_tlp],
                    custom_properties={
                        "labels": ["dynamic"],
                        "created_by_ref": self.identity,
                    },
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "communicates-with", observable["standard_id"], domain_stix.id
                    ),
                    relationship_type="communicates-with",
                    created_by_ref=self.identity,
                    source_ref=observable["standard_id"],
                    target_ref=domain_stix.id,
                    allow_custom=True,
                )
                bundle_objects.append(domain_stix)
                bundle_objects.append(relationship)
        urlinfo = json_report.get("urlinfo")
        if urlinfo:
            for url_dict in urlinfo.get("url"):
                url_stix = stix2.URL(
                    value=url_dict["@name"],
                    object_marking_refs=[self._default_tlp],
                    custom_properties={
                        "labels": ["dynamic"],
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
        ipinfo = json_report.get("ipinfo")
        if ipinfo:
            for ip_dict in ipinfo.get("ip"):
                ip_value = ip_dict["@ip"]
                if ipaddress.ip_address(ip_value).is_private:
                    self.helper.log_debug(f"Skipping private IP: {ip_value}")
                    continue
                ip_stix = stix2.IPv4Address(
                    value=ip_value,
                    object_marking_refs=[self._default_tlp],
                    custom_properties={
                        "labels": ["dynamic"],
                        "created_by_ref": self.identity,
                    },
                )
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "communicates-with", observable["standard_id"], ip_stix.id
                    ),
                    relationship_type="communicates-with",
                    created_by_ref=self.identity,
                    source_ref=observable["standard_id"],
                    target_ref=ip_stix.id,
                    allow_custom=True,
                )
                bundle_objects.append(ip_stix)
                bundle_objects.append(relationship)
        return bundle_objects

    def _process_message(self, data: Dict):
        observable = data["enrichment_entity"]
        return self._process_observable(observable)

    def run(self):
        self.helper.listen(message_callback=self._process_message)
