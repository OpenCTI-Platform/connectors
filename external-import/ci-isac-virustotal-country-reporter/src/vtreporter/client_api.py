## the idea behind this:
# 1. perform initial intelligence search to gather list of recent AU files https://virustotal.com/api/v3/intelligence/search?query=entity:file submitter:AU
# 2. perform intel search to get similar files for each one https://github.com/VirusTotal/vt-py/blob/master/examples/search_similar_files.py
# 3. write a report, relate files to report

import urllib
import uuid
from datetime import datetime, timedelta, timezone

import isodate
import requests
import stix2.v21 as stix2

QUERY_TEMPLATE = "entity:file submitter:{country} fs:{start_date}+ fs:{end_date}- p:1+"
LIMIT = "300"


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="CI-ISAC Australia",
            description="CI-ISAC is Australia's leading non-profit dedicated to strengthening the nation's cyber resilience through collaborative intelligence sharing and collective defence.",
        )

        # Parse markings from config
        t = str(self.config.report_markings).casefold()
        if "WHITE".casefold() in t:
            self.report_markings = stix2.TLP_WHITE
        elif "GREEN".casefold() in t:
            self.report_markings = stix2.TLP_GREEN
        elif "AMBER".casefold() in t:
            self.report_markings = stix2.TLP_AMBER
        elif "RED".casefold() in t:
            self.report_markings = stix2.TLP_RED
        t = str(self.config.file_markings).casefold()
        if "WHITE".casefold() in t:
            self.file_markings = stix2.TLP_WHITE
        elif "GREEN".casefold() in t:
            self.file_markings = stix2.TLP_GREEN
        elif "AMBER".casefold() in t:
            self.file_markings = stix2.TLP_AMBER
        elif "RED".casefold() in t:
            self.file_markings = stix2.TLP_RED

        # Define headers in session and update when needed
        headers = {"Accept": "application/json", "x-apikey": self.config.api_key}

        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response.json()

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def filter_data(self, data):
        """
        Removes non-useful data: items with a threat severity of LOW with only 1 source, or a threat severity of NONE.
        Returns the filtered dataset. Could probably be an ugly lambda, but no
        """
        pass

        filtered_data = []
        for item in data:
            attributes = item.get("attributes", {})
            threat_severity = attributes.get("threat_severity", {})
            threat_severity_level = threat_severity.get("threat_severity_level")
            unique_sources = attributes.get("unique_sources")

            # Exclude items with SEVERITY_NONE or SEVERITY_LOW with 1 unique source
            # Deliberately denylisting non/low rather than allowlisting others because I'd prefer to fail-open rather than fail-closed.
            if threat_severity_level == "SEVERITY_NONE":
                continue
            if threat_severity_level == "SEVERITY_LOW" and unique_sources == 1:
                continue

            filtered_data.append(item)
        return filtered_data

    def convert_to_stix(self, data):
        """
        Converts API responses to STIX
        Also grabs similar and dropped files for HIGH risk files, then converts them to stix too and relates them to the parent.
        """
        stix_objects = []

        for item in data:

            attributes = item["attributes"]
            name = attributes.get("meaningful_name")
            if name is None:
                name = "unknown"

            # Get threat_severity
            threat_severity = attributes.get("threat_severity", {})
            threat_severity_level = threat_severity.get("threat_severity_level")

            # Get AV detections
            threat_severity_data = threat_severity.get("threat_severity_data", {})
            popular_threat_category = threat_severity_data.get(
                "popular_threat_category"
            )
            num_av_detections = threat_severity_data.get("num_av_detections")
            if num_av_detections is None:
                num_av_detections = threat_severity_data.get("num_gav_detections")

            # Build labels
            labels = attributes.get("tags", [])
            if (
                popular_threat_category
                and popular_threat_category.strip() != "None"
                and popular_threat_category.strip() not in labels
            ):
                labels.append(f"{popular_threat_category.strip()}")
            if threat_severity_level and threat_severity_level not in labels:
                labels.append(f"{threat_severity_level}")

            # Add labels based on config
            if self.config.file_labels:
                for l in self.config.file_labels.split(","):
                    labels.append(l)

            first_submission_date = (
                self.convert_epoch_to_readable(attributes.get("first_submission_date"))
                if attributes.get("first_submission_date")
                else "N/A"
            )

            # Construct description
            description = (
                f"[ {name.strip()} ] was first submitted on [ {first_submission_date} ] and is classified as a [ {popular_threat_category} ] "
                f"with [ {num_av_detections} ] AV detections. The threat level is [ {threat_severity_level} ] with "
                f"[ {attributes.get("unique_sources")} ] unique samples."
            )

            # Add additional names
            x_opencti_additional_names = []
            for n in attributes["names"]:
                x_opencti_additional_names.append(n)

            # Calculate hashes, making sure not to create null variables or OpenCTI gets sad
            hashes = {"SHA256": item["id"]}
            if attributes.get("sha1"):
                hashes["SHA1"] = attributes.get("sha1")
            if attributes.get("md5"):
                hashes["MD5"] = attributes.get("md5")
            if attributes.get("imphash"):
                hashes["imphash"] = attributes.get("imphash")

            # Build STIX2 File and add it to the list
            stix_object = stix2.File(
                type="file",
                name=name.strip(),
                description=description,
                hashes=hashes,
                size=attributes.get("size"),
                mime_type=attributes.get("MIMEType"),
                created_by_ref=self.identity["standard_id"],
                object_marking_refs=self.file_markings,
                labels=labels,
                external_references=[
                    {
                        "source_name": "VirusTotal",
                        "url": item["links"]
                        .get("self")
                        .replace("/api/v3/files/", "/gui/file/"),
                    }
                ],
                allow_custom=True,
                custom_properties={
                    "x_opencti_additional_names": x_opencti_additional_names
                },
            )
            stix_objects.append(stix_object)

            # Get related files for high severity items
            if threat_severity_level == "SEVERITY_HIGH":
                # Try to get related files using SHA-256, SHA-1, or MD5
                for hash_type in ["SHA256", "SHA1", "MD5"]:
                    hash_value = stix_object["hashes"].get(hash_type)
                    if hash_value:
                        try:

                            for type in ["similar_files", "dropped_files"]:

                                # Get similar files
                                related_r = self._request_data(
                                    f"{self.config.api_url}/files/{hash_value}/{type}"
                                )
                                related = related_r.get("data", [])

                                # Add only related files with SEVERITY_HIGH or SEVERITY_MEDIUM
                                for rf in related:

                                    rf_attributes = rf.get("attributes", {})
                                    rf_threat_severity = rf_attributes.get(
                                        "threat_severity", {}
                                    )
                                    rf_threat_severity_level = rf_threat_severity.get(
                                        "threat_severity_level"
                                    )

                                    if rf_threat_severity_level in (
                                        "SEVERITY_HIGH",
                                        "SEVERITY_MEDIUM",
                                    ):
                                        rf_name = rf_attributes.get("meaningful_name")
                                        if rf_name is None:
                                            rf_name = "unknown"

                                        # Apply labels to related files
                                        rf_labels = rf_attributes.get("tags", [])
                                        rf_threat_severity_data = (
                                            rf_threat_severity.get(
                                                "threat_severity_data", {}
                                            )
                                        )
                                        rf_popular_threat_category = (
                                            rf_threat_severity_data.get(
                                                "popular_threat_category"
                                            )
                                        )

                                        if (
                                            rf_popular_threat_category
                                            and rf_popular_threat_category.strip()
                                            != "None"
                                            and rf_popular_threat_category.strip()
                                            not in rf_labels
                                        ):
                                            rf_labels.append(
                                                f"{rf_popular_threat_category.strip()}"
                                            )
                                        if (
                                            rf_threat_severity_level
                                            and rf_threat_severity_level
                                            not in rf_labels
                                        ):
                                            rf_labels.append(
                                                f"{rf_threat_severity_level}"
                                            )

                                        # Add labels based on config
                                        if self.config.file_labels:
                                            for l in self.config.file_labels.split(","):
                                                rf_labels.append(l)

                                        # add additional names
                                        rf_x_opencti_additional_names = []
                                        for n in rf_attributes["names"]:
                                            rf_x_opencti_additional_names.append(n)

                                        rf_description = f"[{type}] from to {name} with SHA-256: {rf['id']}. [ {rf_name.strip()} ] is classified as a [ {rf_popular_threat_category} ]. The threat level is [ {rf_threat_severity_level} ] with [ {rf_attributes.get("unique_sources")} ] unique samples."

                                        # Make the STIX2 object and add it to the list
                                        rf_stix = stix2.File(
                                            name=rf_name.strip(),
                                            description=rf_description,
                                            hashes=rf_attributes.get("hashes"),
                                            labels=rf_labels,
                                            size=attributes.get("size"),
                                            mime_type=attributes.get("MIMEType"),
                                            created_by_ref=self.identity["standard_id"],
                                            object_marking_refs=self.file_markings,
                                            external_references=[
                                                {
                                                    "source_name": "VirusTotal",
                                                    "url": rf["links"]
                                                    .get("self")
                                                    .replace(
                                                        "/api/v3/files/", "/gui/file/"
                                                    ),
                                                }
                                            ],
                                            allow_custom=True,
                                            custom_properties={
                                                "x_opencti_additional_names": rf_x_opencti_additional_names
                                            },
                                        )
                                        stix_objects.append(rf_stix)

                                        # Also add a relationship between the parent and related files
                                        if type.casefold() == "dropped_files":
                                            relationship_type = "dropped by"
                                            rt = "drops"
                                        else:
                                            relationship_type = "related to"
                                            rt = "related-to"
                                        relationship = stix2.Relationship(
                                            type="relationship",
                                            description=f"Source file is {relationship_type} target file.",
                                            relationship_type=rt,
                                            source_ref=stix_object.id,
                                            target_ref=rf_stix.id,
                                        )
                                        stix_objects.append(relationship)

                            break  # Stop checking hashes once a valid related file is found
                        except requests.exceptions.HTTPError as e:
                            print(f"Error getting related files for {hash_value}: {e}")
        return stix_objects

    def convert_epoch_to_readable(self, epoch_time):
        return datetime.fromtimestamp(epoch_time, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )

    def get_entities(self):
        try:

            # start_date = now() - duration_period in seconds
            # duration_period is in ISO 8601 format.
            duration_period_in_seconds = 86400
            try:
                duration_period_in_seconds = isodate.parse_duration(
                    self.config.duration_period
                ).total_seconds()
                self.helper.connector_logger.warning(
                    f"[API] duration_period parsed successfully: ISO-8601 {self.config.duration_period} == {duration_period_in_seconds} seconds."
                )
            except Exception:
                self.helper.connector_logger.warning(
                    "[API] duration_period probably not valid ISO 8601, defaulting to 1-day history."
                )

            # Start the search at now() - duration, e.g. duration=1day, start_date=yesterday
            start_date = (
                datetime.now() - timedelta(seconds=duration_period_in_seconds)
            ).strftime("%Y-%m-%d")
            end_date = datetime.now().strftime("%Y-%m-%d")

            # Construct VT API query
            query = QUERY_TEMPLATE.format(
                country=str(self.config.country).lower(),
                start_date=start_date,
                end_date=end_date,
            )

            all_api_data = []

            base_url = f"{self.config.api_url}/intelligence/search"
            query_url = f"{base_url}?query={urllib.parse.quote(query)}&limit={LIMIT}&descriptors_only=false"

            self.helper.connector_logger.info(f"[API] Running query: {query}")

            while query_url:
                response = self._request_data(query_url)
                all_api_data.extend(response["data"])

                # Get the next URL from the links section, if available
                query_url = response.get("links", {}).get("next")

            # Filter data to exclude SEVERITY_NONE and severity_low with 1 unique source
            filtered_data = self.filter_data(all_api_data)

            # Convert filtered data to STIX
            stix_data = self.convert_to_stix(filtered_data)

            # Create refs
            object_refs = []
            for s in stix_data:
                object_refs.append(s.id)

            # Write a description
            num_high = 0
            num_med = 0
            for s in stix_data:
                if "SEVERITY_HIGH" in s.description:
                    num_high += 1
                if "SEVERITY_MEDIUM" in s.description:
                    num_med += 1

            # Add labels based on config
            labels = []
            if self.config.report_labels:
                for l in self.config.file_labels.split(","):
                    labels.append(l)

            description = f"This run of the VirusTotal Regular Report scanned new file uploads from {self.config.country} between {start_date} and {end_date}. It grabs any HIGH or MEDIUM severity files, then also grabs any related HIGH or MEDIUM severity files. This run, it reports {num_high+num_med} new files, {num_high} high risk and {num_med} medium risk. "

            # Create report object
            title = f"VT AU Submission [{start_date} to {end_date}]"
            r = stix2.Report(
                id="report--" + str(uuid.uuid4()),
                report_types=self.config.threat_types,
                published=datetime.strptime(start_date, "%Y-%m-%d"),
                name=title,
                description=description,
                created_by_ref=self.identity["standard_id"],
                object_marking_refs=self.report_markings,
                confidence=self.config.confidence,
                labels=labels,
                object_refs=object_refs,
                allow_custom=True,
                custom_properties={
                    "x_opencti_reliability": self.config.reliability,
                },
            )

            # Add the report to stix_data
            stix_data.append(r)

            return stix_data

        except Exception as err:
            self.helper.connector_logger.error(err)