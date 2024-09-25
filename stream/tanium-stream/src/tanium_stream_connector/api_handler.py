import requests
from pycti import OpenCTIConnectorHelper
from stix2slider import slide_string
from stix2slider.options import initialize_options


class TaniumApiHandler:
    def __init__(self, helper, config):
        """
        Init Tanium API handler.
        :param helper: PyCTI helper instance
        :param config: Connector config variables
        """
        self.helper = helper
        self.config = config

        self.source_id = self._get_source_id()

    def get_url(self) -> str:
        return self.config.tanium_url

    def _get_source_id(self) -> str:
        """
        Set OpenCTI as intelligence source.
        """
        source = None
        sources = self._request_data(
            "GET", "/plugin/products/threat-response/api/v1/sources"
        )
        for source_entry in sources:
            if source_entry["name"] == "OpenCTI":
                source = source_entry
        if source is None:
            source = self._request_data(
                "POST",
                "/plugin/products/threat-response/api/v1/sources",
                json={
                    "type": "api-client",
                    "name": "OpenCTI",
                    "description": "Cyber Threat Intelligence knowledge imported from OpenCTI.",
                },
            )
        return str(source["id"])

    def _request_data(
        self, method, url_path, params=None, data=None, json=None, headers=None
    ) -> dict | str | None:
        try:
            url = self.config.tanium_url + url_path
            request_headers = {
                "session": self.config.tanium_token,
                "content-type": "application/json",
            }
            if headers:
                request_headers.update(headers)

            response = None
            if method == "GET":
                response = requests.get(
                    url,
                    params=params,
                    headers=request_headers,
                    verify=self.config.tanium_ssl_verify,
                )
            elif method == "POST":
                response = requests.post(
                    url,
                    data=data,
                    json=json,
                    headers=request_headers,
                    verify=self.config.tanium_ssl_verify,
                )
            elif method == "PUT":
                response = requests.put(
                    url,
                    data=data,
                    json=json,
                    headers=request_headers,
                    verify=self.config.tanium_ssl_verify,
                )
            elif method == "DELETE":
                response = requests.delete(
                    url,
                    headers=request_headers,
                    verify=self.config.tanium_ssl_verify,
                )
            if response is None:
                raise ValueError("HTTP method not supported")

            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP {method} Request to endpoint",
                {"url_path": url_path},
            )

            if response.headers.get("content-type") == "application/json":
                return response.json()["data"]
            else:
                return response.text

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while fetching data: ",
                {"url_path": f"{method} {url_path}", "error": str(err)},
            )
            return None

    def create_indicator_stix(self, entity):
        # Export to STIX bundle
        stix2_bundle = self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
            "Indicator",
            entity["id"],
            "simple",
            None,
            True,
        )
        stix_entity = [e for e in stix2_bundle["objects"] if e["id"] == entity["id"]][0]
        if "indicator_types" not in stix_entity:
            stix_entity["indicator_types"] = "unknown"
        # Convert the STIX 2 bundle in STIX 1
        initialize_options()
        stix_indicator = slide_string(stix2_bundle)

        url_path = (
            f"/plugin/products/threat-response/api/v1/sources/{self.source_id}/intels"
        )
        intel_document = self._request_data(
            "POST",
            url_path,
            data=stix_indicator,
            headers={
                "content-type": "application/xml",
                "type": "stix",
            },
        )
        return intel_document

    def create_indicator_yara(self, entity):
        url_path = (
            f"/plugin/products/threat-response/api/v1/sources/{self.source_id}/intels"
        )
        intel_document = self._request_data(
            "POST",
            url_path,
            data=entity["pattern"],
            headers={
                "content-type": "application/octet-stream",
                "content-disposition": f"attachment; filename={entity['name']}.yara",
                "type": "yara",
                "name": entity["name"].strip(),
                "description": entity["description"].replace("\n", " ").strip(),
            },
        )
        return intel_document

    def create_indicator_tanium_signal(self, entity):
        platforms = []
        if "x_mitre_platforms" in entity and len(entity["x_mitre_platforms"]) > 0:
            for x_mitre_platform in entity["x_mitre_platforms"]:
                if x_mitre_platform in ["Linux", "Windows", "macOS"]:
                    platforms.append(
                        x_mitre_platform.lower()
                        if x_mitre_platform != "macOS"
                        else "mac"
                    )

        url_path = (
            f"/plugin/products/threat-response/api/v1/sources/{self.source_id}/intels"
        )
        intel_document = self._request_data(
            "POST",
            url_path,
            json={
                "name": entity["name"],
                "description": entity["description"],
                "platforms": platforms,
                "contents": entity["pattern"],
            },
        )
        return intel_document

    def create_observable(self, entity):
        intel_type = None
        value = ""
        name = None
        if entity["type"] == "file":
            intel_type = "File Hashes"
            if "hashes" in entity:
                if isinstance(entity["hashes"], list):
                    hashes = entity["hashes"]
                    entity["hashes"] = {}
                    for hash in hashes:
                        entity["hashes"][hash["algorithm"]] = hash["hash"]
                if "MD5" in entity["hashes"]:
                    value = value + entity["hashes"]["MD5"] + "\n"
                    name = entity["hashes"]["MD5"]
                if "SHA-1" in entity["hashes"]:
                    value = value + entity["hashes"]["SHA-1"] + "\n"
                    name = entity["hashes"]["SHA-1"]
                if "SHA-256" in entity["hashes"]:
                    value = value + entity["hashes"]["SHA-256"] + "\n"
                    name = entity["hashes"]["SHA-256"]
        elif entity["type"] in [
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
            "hostname",
        ]:
            intel_type = "Network Indicators"
            value = entity["value"]
            name = entity["value"]
        if intel_type is None or len(value) == 0:
            return None

        openioc = self._request_data(
            "POST",
            "/plugin/products/threat-response/api/v1/intels/quick-add",
            json={
                "exact": True,
                "name": name,
                "type": intel_type,
                "text": value,
            },
        )
        if not openioc:
            raise ValueError("Error creating the OpenIOC: " + value)

        url_path = (
            f"/plugin/products/threat-response/api/v1/sources/{self.source_id}/intels"
        )
        intel_document = self._request_data(
            "POST",
            url_path,
            data=openioc,
            headers={
                "content-type": "application/xml",
                "type": "openioc",
            },
        )
        return intel_document

    def create_reputation(self, entity):
        if "hashes" in entity:
            entry = {"list": "blacklist"}
            if isinstance(entity["hashes"], list):
                hashes = entity["hashes"]
                entity["hashes"] = {}
                for hash in hashes:
                    entity["hashes"][hash["algorithm"]] = hash["hash"]
            if "MD5" in entity["hashes"]:
                entry["md5"] = entity["hashes"]["MD5"]
                entry["uploadedHash"] = entity["hashes"]["MD5"]
            else:
                entry["md5"] = ""
            if "SHA-1" in entity["hashes"]:
                entry["sha1"] = entity["hashes"]["SHA-1"]
                entry["uploadedHash"] = entity["hashes"]["SHA-1"]
            else:
                entry["sha1"] = ""
            if "SHA-256" in entity["hashes"]:
                entry["sha256"] = entity["hashes"]["SHA-256"]
                entry["uploadedHash"] = entity["hashes"]["SHA-256"]
            else:
                entry["sha256"] = ""

            entity_description = OpenCTIConnectorHelper.get_attribute_in_extension(
                "description", entity
            )
            if entity_description:
                entry["notes"] = entity_description
            if "labels" in entity:
                entry["notes"] = ",".join(entity["labels"])

            url_path = (
                "/plugin/products/reputation/v3/reputations/custom/upload?append=true"
            )
            self._request_data(
                "POST",
                url_path,
                json=[entry],
            )
        return None

    def update_indicator_stix(self, intel_id, entity):
        # Export to STIX bundle
        stix2_bundle = self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type="Indicator",
            entity_id=entity["id"],
            mode="simple",
            no_custom_attributes=True,
        )
        # Convert the STIX 2 bundle in STIX 1
        try:
            initialize_options()
            stix_indicator = slide_string(stix2_bundle)

            url_path = f"/plugin/products/threat-response/api/v1/intels/{intel_id}"
            intel_document = self._request_data(
                "PUT",
                url_path,
                data=stix_indicator,
                headers={
                    "content-type": "application/xml",
                    "type": "stix",
                },
            )
            return intel_document
        except Exception as e:
            self.helper.connector_logger.error(str(e))
            return None

    def update_indicator_yara(self, intel_id, entity):
        filename = f"{entity['name']}.yara"
        url_path = f"/plugin/products/threat-response/api/v1/intels/{intel_id}"
        intel_document = self._request_data(
            "PUT",
            url_path,
            data={
                "filename": filename,
                "document": entity["pattern"],
                "name": entity["name"],
                "description": entity["description"],
            },
            headers={
                "content-type": "application/octet-stream",
                "content-disposition": "attachment; filename=" + filename,
                "type": "yara",
                "name": filename.strip(),
                "description": entity["description"].replace("\n", " ").strip(),
            },
        )
        return intel_document

    def update_indicator_tanium_signal(self, intel_id, entity):
        platforms = []
        if OpenCTIConnectorHelper.get_attribute_in_mitre_extension("platforms", entity):
            for x_mitre_platform in entity["x_mitre_platforms"]:
                if x_mitre_platform in ["Linux", "Windows", "macOS"]:
                    platforms.append(
                        x_mitre_platform.lower()
                        if x_mitre_platform != "macOS"
                        else "mac"
                    )

        url_path = f"/plugin/products/threat-response/api/v1/intels/{intel_id}"
        intel_document = self._request_data(
            "PUT",
            url_path,
            json={
                "name": entity["name"],
                "description": entity["description"],
                "platforms": platforms,
                "contents": entity["pattern"],
            },
        )
        return intel_document

    def update_observable(self, intel_id, entity):
        intel_type = None
        value = ""
        name = None
        if entity["type"] == "file":
            intel_type = "file_hash"
            if "hashes" in entity:
                if isinstance(entity["hashes"], list):
                    hashes = entity["hashes"]
                    entity["hashes"] = {}
                    for hash in hashes:
                        entity["hashes"][hash["algorithm"]] = hash["hash"]
                if "MD5" in entity["hashes"]:
                    value = value + entity["hashes"]["MD5"] + "\n"
                    name = entity["hashes"]["MD5"]
                if "SHA-1" in entity["hashes"]:
                    value = value + entity["hashes"]["SHA-1"] + "\n"
                    name = entity["hashes"]["SHA-1"]
                if "SHA-256" in entity["hashes"]:
                    value = value + entity["hashes"]["SHA-256"] + "\n"
                    name = entity["hashes"]["SHA-256"]
        elif entity["type"] in [
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
            "hostname",
        ]:
            intel_type = "ip_or_host"
            value = entity["value"]
            name = entity["value"]
        if intel_type is None or not value:
            return None

        entity_description = OpenCTIConnectorHelper.get_attribute_in_extension(
            "description", entity
        )

        openioc = self._request_data(
            "POST",
            "/plugin/products/threat-response/api/v1/intels/quick-add",
            json={
                "exact": True,
                "name": name,
                "description": (
                    entity_description if entity_description is not None else ""
                ),
                "type": intel_type,
                "text": value,
            },
        )
        if not openioc:
            raise ValueError("Error creating the OpenIOC: " + value)

        url_path = f"/plugin/products/threat-response/api/v1/intels/{intel_id}"
        intel_document = self._request_data(
            "PUT",
            url_path,
            data=openioc,
            headers={
                "content-type": "application/xml",
                "type": "ioc",
            },
        )
        return intel_document

    def delete_intel(self, intel_id):
        self._request_data(
            "DELETE", f"/plugin/products/threat-response/api/v1/intels/?id={intel_id}"
        )

    def delete_reputation(self, reputation_id):
        self._request_data(
            "DELETE",
            f"/plugin/products/reputation/v3/reputations/custom/{reputation_id}",
        )

    def deploy_intel(self):
        self._request_data(
            "POST", "/plugin/products/threat-response/api/v1/intel/deploy"
        )

    def trigger_quickscan(self, intel_document_id):
        if self.config.tanium_auto_ondemand_scan:
            for computer_group in self.config.tanium_computer_groups:
                self._request_data(
                    "POST",
                    "/plugin/products/threat-response/api/v1/on-demand-scans",
                    json={
                        "computerGroupId": int(computer_group),
                        "intelDocId": intel_document_id,
                    },
                )

    def add_label(self, intel_id, label):
        url_path = f"/plugin/products/threat-response/api/v1/intels/{intel_id}/labels"
        self._request_data("PUT", url_path, json={"id": label["id"]})

    def get_labels(self, labels):
        tanium_labels = self._request_data(
            "GET",
            "/plugin/products/threat-response/api/v1/labels",
            params={"limit": 500},
        )

        tanium_labels_dict = {}
        for tanium_label in tanium_labels:
            tanium_labels_dict[tanium_label["name"].lower()] = tanium_label

        final_labels = []
        for label in labels:
            if label in tanium_labels_dict:
                final_labels.append(tanium_labels_dict[label])
            else:
                created_label = self._request_data(
                    "POST",
                    "/plugin/products/threat-response/api/v1/labels",
                    json={
                        "name": label,
                        "description": "Label imported from OpenCTI",
                    },
                )
                final_labels.append(created_label)
        return final_labels
