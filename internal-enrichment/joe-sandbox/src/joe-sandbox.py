# coding: utf-8

import ipaddress
import json
import os
import sys
import time
import stix2
import yaml
from pycti import OpenCTIConnectorHelper, StixCoreRelationship, get_config_variable
from io import BytesIO
import jbxapi


class JoeSandboxConnector:
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
            type="Organization", name="Joe Security", description="Joe Security"
        )["standard_id"]

        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )

        # JoeSandbox class instatiation settings from config
        api_key = get_config_variable(
            "JOE_SANDBOX_API_KEY", ["joe_sandbox", "api_key"], config
        )
        # Cloud Pro: https://jbxcloud.joesecurity.org/api
        # Cloud Basic: https://joesandbox.com/api
        api_url = get_config_variable(
            "JOE_SANDBOX_API_URL", ["joe_sandbox", "api_url"], config
        )
        # Cloud Pro: https://jbxcloud.joesecurity.org/analysis
        # Cloud Basic: https://joesandbox.com/analysis
        self._analysis_url = get_config_variable(
            "JOE_SANDBOX_ANALYSIS_URL", ["joe_sandbox", "analysis_url"], config
        )
        accept_tac = get_config_variable(
            "JOE_SANDBOX_ACCEPT_TAC", ["joe_sandbox", "accept_tac"], config
        )
        api_timeout = get_config_variable(
            "JOE_SANDBOX_API_TIMEOUT",
            ["joe_sandbox", "api_timeout"],
            config,
            isNumber=True,
        )
        verify_ssl = get_config_variable(
            "JOE_SANDBOX_VERIFY_SSL", ["joe_sandbox", "verify_ssl"], config
        )
        api_retries = get_config_variable(
            "JOE_SANDBOX_API_RETRIES",
            ["joe_sandbox", "api_retries"],
            config,
            isNumber=True,
        )
        # Must be a json encoded map, see the following link for the format:
        # https://requests.readthedocs.io/en/latest/user/advanced/?highlight=proxy#proxies
        proxies = get_config_variable(
            "JOE_SANDBOX_PROXIES", ["joe_sandbox", "proxies"], config
        )
        if proxies:
            proxies = json.loads(proxies)

        user_agent = get_config_variable(
            "JOE_SANDBOX_USER_AGENT", ["joe_sandbox", "user_agent"], config
        )

        # See https://github.com/joesecurity/jbxapi/blob/master/docs/api.md
        self.joe_sandbox_client = jbxapi.JoeSandbox(
            apikey=api_key,  # The API key
            apiurl=api_url,  # The API url
            # Joe Sandbox Cloud requires accepting the Terms and Conditions.
            # https://jbxcloud.joesecurity.org/resources/termsandconditions.pdf
            accept_tac=accept_tac,
            timeout=api_timeout,  # Timeout in seconds for accessing the API. Raises a ConnectionError on timeout.
            verify_ssl=verify_ssl,  # Enable or disable checking SSL certificates.
            retries=api_retries,  # Number of times requests should be retried if they timeout.
            # Proxy settings, see the requests library for more information:
            # https://requests.readthedocs.io/en/latest/user/advanced/?highlight=proxy#proxies
            proxies=proxies,
            # The user agent. Use this when you write an integration with Joe Sandbox
            # so that it is possible to track how often an integration is being used.
            user_agent=user_agent,
        )

        self._report_types = get_config_variable(
            "JOE_SANDBOX_REPORT_TYPES", ["joe_sandbox", "report_types"], config
        ).split(",")

        # JoeSandbox submit settings from config
        self._systems = get_config_variable(
            "JOE_SANDBOX_SYSTEMS", ["joe_sandbox", "systems"], config
        ).split(",")
        self._analysis_time = get_config_variable(
            "JOE_SANDBOX_ANALYSIS_TIME",
            ["joe_sandbox", "analysis_time"],
            config,
            isNumber=True,
        )
        self._internet_access = get_config_variable(
            "JOE_SANDBOX_INTERNET_ACCESS", ["joe_sandbox", "internet_access"], config
        )
        self._internet_simulation = get_config_variable(
            "JOE_SANDBOX_INTERNET_SIMULATION",
            ["joe_sandbox", "internet_simulation"],
            config,
        )
        self._hybrid_code_analysis = get_config_variable(
            "JOE_SANDBOX_HYBRID_CODE_ANALYSIS",
            ["joe_sandbox", "hybrid_code_analysis"],
            config,
        )
        self._hybrid_decompilation = get_config_variable(
            "JOE_SANDBOX_HYBRID_DECOMPILATION",
            ["joe_sandbox", "hybrid_decompilation"],
            config,
        )
        self._report_cache = get_config_variable(
            "JOE_SANDBOX_REPORT_CACHE", ["joe_sandbox", "report_cache"], config
        )
        self._apk_instrumentation = get_config_variable(
            "JOE_SANDBOX_APK_INSTRUMENTATION",
            ["joe_sandbox", "apk_instrumentation"],
            config,
        )
        self._amsi_unpacking = get_config_variable(
            "JOE_SANDBOX_AMSI_UNPACKING", ["joe_sandbox", "amsi_unpacking"], config
        )
        self._ssl_inspection = get_config_variable(
            "JOE_SANDBOX_SSL_INSPECTION", ["joe_sandbox", "ssl_inspection"], config
        )
        self._vba_instrumentation = get_config_variable(
            "JOE_SANDBOX_VBA_INSTRUMENTATION",
            ["joe_sandbox", "vba_instrumentation"],
            config,
        )
        self._js_instrumentation = get_config_variable(
            "JOE_SANDBOX_JS_INSTRUMENTATION",
            ["joe_sandbox", "js_instrumentation"],
            config,
        )
        self._java_jar_tracing = get_config_variable(
            "JOE_SANDBOX_JAVA_JAR_TRACING", ["joe_sandbox", "java_jar_tracing"], config
        )
        self._dotnet_tracing = get_config_variable(
            "JOE_SANDBOX_DOTNET_TRACING", ["joe_sandbox", "dotnet_tracing"], config
        )
        self._start_as_normal_user = get_config_variable(
            "JOE_SANDBOX_START_AS_NORMAL_USER",
            ["joe_sandbox", "start_as_normal_user"],
            config,
        )
        self._system_date = get_config_variable(
            "JOE_SANDBOX_SYSTEM_DATE", ["joe_sandbox", "system_date"], config
        )
        self._language_and_locale = get_config_variable(
            "JOE_SANDBOX_LANGUAGE_AND_LOCALE",
            ["joe_sandbox", "language_and_locale"],
            config,
        )
        self._localized_internet_country = get_config_variable(
            "JOE_SANDBOX_LOCALIZED_INTERNET_COUNTRY",
            ["joe_sandbox", "localized_internet_country"],
            config,
        )
        self._email_notification = get_config_variable(
            "JOE_SANDBOX_EMAIL_NOTIFICATION",
            ["joe_sandbox", "email_notification"],
            config,
        )
        self._archive_no_unpack = get_config_variable(
            "JOE_SANDBOX_ARCHIVE_NO_UNPACK",
            ["joe_sandbox", "archive_no_unpack"],
            config,
        )
        self._hypervisor_based_inspection = get_config_variable(
            "JOE_SANDBOX_HYPERVISOR_BASED_INSPECTION",
            ["joe_sandbox", "hypervisor_based_inspection"],
            config,
        )
        self._fast_mode = get_config_variable(
            "JOE_SANDBOX_FAST_MODE", ["joe_sandbox", "fast_mode"], config
        )
        self._secondary_results = get_config_variable(
            "JOE_SANDBOX_SECONDARY_RESULTS",
            ["joe_sandbox", "secondary_results"],
            config,
        )

        self._cookbook = None
        cookbook_file_path = get_config_variable(
            "JOE_SANDBOX_COOKBOOK_FILE_PATH",
            ["joe_sandbox", "cookbook_file_path"],
            config,
        )
        if cookbook_file_path and os.path.exists(cookbook_file_path):
            with open(cookbook_file_path, "rb") as f:
                self._cookbook = BytesIO(f.read())

        self._document_password = get_config_variable(
            "JOE_SANDBOX_DOCUMENT_PASSWORD",
            ["joe_sandbox", "document_password"],
            config,
        )
        self._archive_password = get_config_variable(
            "JOE_SANDBOX_ARCHIVE_PASSWORD", ["joe_sandbox", "archive_password"], config
        )
        self._command_line_argument = get_config_variable(
            "JOE_SANDBOX_COMMAND_LINE_ARGUMENT",
            ["joe_sandbox", "command_line_argument"],
            config,
        )
        self._live_interaction = get_config_variable(
            "JOE_SANDBOX_LIVE_INTERACTION", ["joe_sandbox", "live_interaction"], config
        )
        self._encrypt_with_password = get_config_variable(
            "JOE_SANDBOX_ENCRYPT_WITH_PASSWORD",
            ["joe_sandbox", "encrypt_with_password"],
            config,
        )
        self._browser = get_config_variable(
            "JOE_SANDBOX_BROWSER", ["joe_sandbox", "browser"], config
        )
        self._url_reputation = get_config_variable(
            "JOE_SANDBOX_URL_REPUTATION", ["joe_sandbox", "url_reputation"], config
        )
        self._export_to_jbxview = get_config_variable(
            "JOE_SANDBOX_EXPORT_TO_JBXVIEW",
            ["joe_sandbox", "export_to_jbxview"],
            config,
        )
        self._delete_after_days = get_config_variable(
            "JOE_SANDBOX_DELETE_AFTER_DAYS",
            ["joe_sandbox", "delete_after_days"],
            config,
            isNumber=True,
        )
        self._priority = get_config_variable(
            "JOE_SANDBOX_PRIORITY", ["joe_sandbox", "priority"], config, isNumber=True
        )

        self._default_tlp = get_config_variable(
            "JOE_SANDBOX_DEFAULT_TLP", ["joe_sandbox", "default_tlp"], config
        ).lower()

        self._yara_color = get_config_variable(
            "JOE_SANDBOX_YARA_COLOR", ["joe_sandbox", "yara_color"], config
        )

        default_color = get_config_variable(
            "JOE_SANDBOX_DEFAULT_COLOR", ["joe_sandbox", "default_color"], config
        )

        # Create default labels
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
            "live-interaction": self._live_interaction,  # Use Live Interaction. Requires user interaction via the web UI. If enabled, disables VBA instrumentation (on Windows).
            "encrypt-with-password": self._encrypt_with_password,  # Encryption password for analyses
            # JOE SANDBOX CLOUD EXCLUSIVE PARAMETERS
            "url-reputation": self._url_reputation,  # Lookup the reputation of URLs and domains to improve the analysis. This option will send URLs and domains to third party services and WHOIS servers!.
            "export-to-jbxview": self._export_to_jbxview,  # Export the report(s) from this analysis to Joe Sandbox View.
            "delete-after-days": self._delete_after_days,  # Delete the analysis after X days. If not set, the default value is used
            ## ON PREMISE EXCLUSIVE PARAMETERS
            "priority": self._priority,  # Integer value between 1 and 10, higher value means higher priority.
        }

        submission_dict = {}
        if observable["entity_type"] == "Url":
            self.helper.log_info(
                f"Submitting {observable['observable_value']} to JoeSandbox for analysis..."
            )
            # True = use the browser for analysis, False = download/execute
            # Submit the url to Joe Sandbox
            if self._browser:
                submission_dict = self.joe_sandbox_client.submit_url(
                    url=observable["observable_value"], params=params
                )
            else:
                submission_dict = self.joe_sandbox_client.submit_sample_url(
                    url=observable["observable_value"], params=params
                )
        elif observable["entity_type"] == "Artifact":
            # Download the Artifact from OpenCTI
            sample = self._download_artifact(observable)
            self.helper.log_info(
                f"Submitting {observable['importFiles'][0]['name']} to JoeSandbox for analysis..."
            )
            # Submit the sample to Joe Sandbox
            submission_dict = self.joe_sandbox_client.submit_sample(
                sample, cookbook=self._cookbook, params=params
            )
        else:
            raise ValueError(
                f"Failed to process observable, {observable['entity_type']} is not a supported entity type."
            )

        self.helper.log_info(json.dumps(submission_dict, indent=2))

        # Get the submission id
        submission_id = submission_dict["submission_id"]

        # Process submission
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

        # Wait for all analyses to finish
        submission_dict = self._wait_for_analyses(submission_id)
        self.helper.log_info(json.dumps(submission_dict, indent=2))

        # Process all of the analyses
        bundle_objects = self._process_analyses(
            observable, submission_dict.get("analyses")
        )

        # Set score of the observable
        score = submission_dict.get("most_relevant_analysis").get("score")
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"], input={"key": "x_opencti_score", "value": str(score)}
        )

        # Serialize and send bundles
        if bundle_objects:
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
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

            # Sleep for a second before attempting to check on the analyses
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

            # Attach external reference
            analysis_url = f"{self._analysis_url}/{webid}"
            external_reference = self.helper.api.external_reference.create(
                source_name=f"Joe Sandbox Analysis [{detection}-{threatname}-{webid}]",
                url=analysis_url,
                description=f"Joe Sandbox Analysis, Web ID: {webid}",
            )
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=observable["id"], external_reference_id=external_reference["id"]
            )

            # Upload the html management report to the external reference files
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

            # Upload the html report to the external reference files
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
                    # Upload the iochtml report to the external reference files
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
                    # Upload the full JSON report to the external reference files
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
                    # Upload the iocjson report to the external reference files
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

            # Only available in Cloud Pro
            if "json" in self._report_types:
                try:
                    name, json_report = self.joe_sandbox_client.analysis_download(
                        webid, "json", password=self._encrypt_with_password
                    )

                    # Handle the JSON report
                    bundle_objects = self._process_json_report(
                        self, observable, json_report
                    )

                    # Upload the full JSON report to the external reference files
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

            # Only available in Cloud Pro
            if "lightjsonfixed" in self._report_types:
                try:
                    name, json_report = self.joe_sandbox_client.analysis_download(
                        webid, "lightjsonfixed", password=self._encrypt_with_password
                    )

                    # Handle the JSON report
                    bundle_objects = self._process_json_report(
                        self, observable, json_report
                    )

                    # Upload the full JSON report to the external reference files
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

            # Only available in Cloud Pro
            if "xml" in self._report_types:
                try:
                    # Upload the full JSON report to the external reference files
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

            # Only available in Cloud Pro
            if "lightxml" in self._report_types:
                try:
                    # Upload the full JSON report to the external reference files
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
                    # Upload the unpacked PE files zip archive
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
                    # Upload the stix report
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
                    # Upload the ida files
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
                    # Upload the misp report
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
                    # Upload the full pdf report
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
                    # Upload the full pdf report
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
                    # Upload the pcap
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
                    # Upload the pcap
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
                    # Upload the pcap
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
                    # Upload the maec report
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
                    # Upload memory dumps
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

        # Extract any identified Malware Configurations
        # and create relationship between Note and observable
        malware_configs = json_report.get("malware_configs")
        if malware_configs:
            configs = malware_configs.get("config")
            for config_dict in configs:
                note = stix2.Note(
                    abstract=f"Malware Configuration ({config_dict['@threatname']})",
                    content=f"```\n{json.dumps(config_dict, indent=2)}\n```",
                    created_by_ref=self.identity,
                    object_marking_refs=[self._default_tlp],
                    object_refs=[observable["standard_id"]],
                )
                bundle_objects.append(note)

        # Extract any identified Yara rules
        # apply as labels to the observable
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

        # Extract Domains and create relationship with observable
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

        # Extract URLs and create relationship with observable
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

        # Extract IPv4 and create relationship with observable
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

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if not observable:
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
        joe_sandbox = JoeSandboxConnector()
        joe_sandbox.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
