import json
import os
import time

import requests
from pycti import OpenCTIConnectorHelper
from stix2 import URL, Note


class URLScanSubmissionsConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.api_key = os.environ.get("URLSCAN_API_KEY", None).lower()
        self.want_results = os.environ.get("CONNECTOR_WANT_RESULTS", "false").lower()
        self.domain_note_count = int(
            os.environ.get("CONNECTOR_DOMAIN_ENRICHMENT_COUNT", 5)
        )

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        if update_existing_data.lower() in ["true", "false"]:
            self.update_existing_data = update_existing_data.lower()
        else:
            msg = f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{self.interval}'. It SHOULD be either `true` or `false`. `false` is assumed. "
            self.helper.log_warning(msg)
            self.update_existing_data = "false"

    def convert_dict_to_markdown_table(self, table: str, data: dict) -> str:
        """Convert a dictionary to a markdown table"""
        unsupported_values = ["", "None", None, [], {}]

        for key, value in data.items():
            if value not in unsupported_values:
                table += f"\\\n | **{key}** | {value} |"

        return table

    def urlscan_fetch_results(self, uuid, counter):
        """Fetch the results of the URLScan API call for the UUID"""

        self.helper.log_info("URLScan fetch result call")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
        }
        response = requests.get(
            "https://urlscan.io/api/v1/result/" + uuid + "/", headers=headers
        )
        if response.status_code == 200:
            response_data = response.json()
            verdict = response_data["verdicts"]
            page = response_data["page"]
            self.helper.log_info("URLScan fetch result call successful")
            return {"verdict": verdict, "page": page}

        elif response.status_code == 404 and counter < 5:
            time.sleep(20)
            return self.urlscan_fetch_results(uuid, counter + 1)
        else:
            self.helper.log_error(f"URLScan fetch result call failed{response}")
            return None

    def urlscan_domain_enrichment(self, observable):
        """
        Fetch the results of the URLScan API call for a domain
        """
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
        }
        response = requests.get(
            "https://urlscan.io/api/v1/search/?q=domain:" + observable["value"],
            headers=headers,
        )

        stix_objects = []
        content = "### URL SCAN RESULTS\n\n"

        if response.status_code == 200:
            self.helper.log_info("URLScan API call successful")
            url_scan_domain_data = response.json()

            if len(url_scan_domain_data["results"]) > 0:
                if len(url_scan_domain_data["results"]) > self.domain_note_count:
                    index = self.domain_note_count + 1
                else:
                    index = len(url_scan_domain_data["results"])

                for result in range(0, index):
                    table = ""
                    table += " \\\n| Field | Value |"
                    table += " \\\n| --- | ---|"
                    result_dict = url_scan_domain_data["results"][result]
                    result_page = result_dict.get("page")
                    result_page["result"] = result_dict.get("result")
                    table = self.convert_dict_to_markdown_table(table, result_page)
                    # result_url=result_dict.get("result")
                    content += table + "\\\n"

                stix_objects.append(
                    Note(
                        type="note",
                        abstract="URLScan Domain search results",
                        content=content,
                        authors=["sudesh"],
                        object_refs=[self.entity_id],
                    )
                )

                # Create the Note object and send it to OpenCTI
                bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                self.helper.log_info(
                    f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
                )

        else:
            self.helper.log_error(f"URLScan API call failed{response}")
        return None

    def urlscan_submission(self, observable):
        headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
        data = {"url": observable["value"], "visibility": "public"}
        response = requests.post(
            "https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)
        )

        if response.status_code == 200:
            self.helper.log_info("URLScan API call successful")
            url_scan_data = response.json()
            if url_scan_data["message"] == "Submission successful":
                external_reference = self.helper.api.external_reference.create(
                    source_name="urlscan.io",
                    external_id=url_scan_data["uuid"],
                    url=url_scan_data["result"],
                )

            if self.want_results == "true":
                results = self.urlscan_fetch_results(url_scan_data["uuid"], 0)
                description = f"**ASN:** {results['page'].get('asn')} \\\n **Country:** {results['page'].get('country')} \\\n **Title:** {results['page'].get('title')} \\\n **Apex_domain:** {results['page'].get('apexDomain')} \\\n **Tls_ValidFrom:** {results['page'].get('tlsValidFrom')} \\\n **TlsIssuer:** {results['page'].get('tlsIssuer')} \\\n **Server:** {results['page'].get('server')} \\\n **Ip:** {results['page'].get('ip')} \\\n **Verdict:** {results['verdict'].get('overall')} \n"

                # adding score verdict and description to the URL object
                score = results["verdict"].get("overall").get("score")
                if score > 0:
                    Url_Object = URL(
                        value=observable["value"],
                        custom_properties={
                            "x_opencti_description": description,
                            "x_opencti_score": score,
                        },
                        allow_custom=True,
                    )
                else:
                    Url_Object = URL(
                        value=observable["value"],
                        custom_properties={"x_opencti_description": description},
                        allow_custom=True,
                    )

                bundle = self.helper.stix2_create_bundle([Url_Object])
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                self.helper.log_info(
                    f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
                )

                # adding labels to the URL object
                for brand in results["verdict"].get("overall").get("brands"):
                    self.helper.api.stix_cyber_observable.add_label(
                        id=observable["id"], label_name=brand
                    )

            self.helper.api.stix_cyber_observable.add_external_reference(
                id=observable["id"], external_reference_id=external_reference["id"]
            )

        else:
            self.helper.log_error(f"URLScan API call failed{response}")

        return None

    def process_message(self, data):
        self.helper.log_info("process data: " + str(data))
        self.entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=self.entity_id)

        # URL enrichment
        if observable["entity_type"] == "Url":
            return self.urlscan_submission(observable)
        # Domain enrichment
        elif observable["entity_type"] == "Domain-Name":
            return self.urlscan_domain_enrichment(observable)
        # Hostname enrichment
        elif observable["entity_type"] == "Hostname":
            return self.urlscan_domain_enrichment(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self.process_message)
