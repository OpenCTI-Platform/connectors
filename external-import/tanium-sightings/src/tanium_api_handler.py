######################
# TANIUM API HANDLER #
######################

import requests
from pycti import OpenCTIConnectorHelper
from stix2slider import slide_string
from stix2slider.options import initialize_options


class TaniumApiHandler:
    def __init__(
        self,
        helper,
        url,
        token,
        ssl_verify=True,
        auto_ondemand_scan=False,
        auto_ondemand_scan_computer_groups=[],
    ):
        # Variables
        self.helper = helper
        self.url = url
        self.token = token
        self.ssl_verify = ssl_verify
        self.auto_ondemand_scan = auto_ondemand_scan
        self.auto_ondemand_scan_computer_groups = auto_ondemand_scan_computer_groups

        # Intelligence documents source
        self.source_id = None
        sources = self._query("get", "/plugin/products/threat-response/api/v1/sources")
        for source in sources:
            if source["name"] == "OpenCTI":
                self.source_id = str(source["id"])
        if self.source_id is None:
            source = self._query(
                "post",
                "/plugin/products/threat-response/api/v1/sources",
                {
                    "type": "api-client",
                    "name": "OpenCTI",
                    "description": "Cyber Threat Intelligence knowledge imported from OpenCTI.",
                },
            )
            self.source_id = str(source["id"])

    def get_url(self):
        return self.url

    def _query(
        self,
        method,
        uri,
        payload=None,
        content_type="application/json",
        type=None,
    ):
        self.helper.log_info("Query " + method + " on " + uri)
        headers = {"session": self.token}
        if method != "upload":
            headers["content-type"] = content_type
        if type is not None:
            headers["type"] = type
        if content_type == "application/octet-stream":
            headers["content-disposition"] = (
                "attachment; filename=" + payload["filename"]
            )
            if "name" in payload:
                headers["name"] = payload["name"].strip()
            if "description" in payload:
                headers["description"] = (
                    payload["description"].replace("\n", " ").strip()
                )
        if method == "get":
            r = requests.get(
                self.url + uri,
                headers=headers,
                params=payload,
                verify=self.ssl_verify,
            )
        elif method == "post":
            if content_type == "application/octet-stream":
                r = requests.post(
                    self.url + uri,
                    headers=headers,
                    data=payload["document"],
                    verify=self.ssl_verify,
                )
            elif type is not None:
                r = requests.post(
                    self.url + uri,
                    headers=headers,
                    data=payload["intelDoc"],
                    verify=self.ssl_verify,
                )
            else:
                r = requests.post(
                    self.url + uri,
                    headers=headers,
                    json=payload,
                    verify=self.ssl_verify,
                )
        elif method == "upload":
            f = open(payload["filename"], "w")
            f.write(payload["content"])
            f.close()
            files = {"hash": open(payload["filename"], "rb")}
            r = requests.post(
                self.url + uri,
                headers=headers,
                files=files,
                verify=self.ssl_verify,
            )
        elif method == "put":
            if type is not None:
                r = requests.put(
                    self.url + uri,
                    headers=headers,
                    data=payload["intelDoc"],
                    verify=self.ssl_verify,
                )
            elif content_type == "application/xml":
                r = requests.put(
                    self.url + uri,
                    headers=headers,
                    data=payload,
                    verify=self.ssl_verify,
                )
            else:
                r = requests.put(
                    self.url + uri,
                    headers=headers,
                    json=payload,
                    verify=self.ssl_verify,
                )
        elif method == "patch":
            r = requests.patch(
                self.url + uri,
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
            )
        elif method == "delete":
            r = requests.delete(self.url + uri, headers=headers, verify=self.ssl_verify)
        else:
            raise ValueError("Unsupported method")
        if r.status_code == 200:
            try:
                return r.json()["data"]
            except:
                return r.text
        elif r.status_code == 401:
            raise ValueError("Query failed, permission denied")
        else:
            self.helper.log_info(r.text)

    def create_indicator_stix(self, entity):
        # Export to STIX bundle
        stix2_bundle = self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type="Indicator",
            entity_id=entity["id"],
            mode="simple",
            no_custom_attribute=True,
        )
        stix_entity = [e for e in stix2_bundle["objects"] if e["id"] == entity["id"]][0]
        if "indicator_types" not in stix_entity:
            stix_entity["indicator_types"] = "unknown"
        # Convert the STIX 2 bundle in STIX 1
        initialize_options()
        stix_indicator = slide_string(stix2_bundle)
        payload = {"intelDoc": stix_indicator}
        intel_document = self._query(
            "post",
            "/plugin/products/threat-response/api/v1/sources/"
            + self.source_id
            + "/intels",
            payload,
            "application/xml",
            "stix",
        )
        return intel_document

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
            payload = {"intelDoc": stix_indicator}
            intel_document = self._query(
                "put",
                "/plugin/products/threat-response/api/v1/intels/" + intel_id,
                payload,
                "application/xml",
                "stix",
            )
            return intel_document
        except Exception as e:
            self.helper.log_error(str(e))
            return None

    def create_indicator_yara(self, entity):
        filename = entity["name"] + ".yara"
        intel_document = self._query(
            "post",
            "/plugin/products/threat-response/api/v1/sources/"
            + self.source_id
            + "/intels",
            {
                "filename": filename,
                "document": entity["pattern"],
                "name": entity["name"],
                "description": entity["description"],
            },
            "application/octet-stream",
            "yara",
        )
        return intel_document

    def update_indicator_yara(self, intel_id, entity):
        filename = entity["name"] + ".yara"
        intel_document = self._query(
            "put",
            "/plugin/products/threat-response/api/v1/intels/" + intel_id,
            {
                "filename": filename,
                "document": entity["pattern"],
                "name": entity["name"],
                "description": entity["description"],
            },
            "application/octet-stream",
            "yara",
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
        intel_document = self._query(
            "post",
            "/plugin/products/threat-response/api/v1/sources/"
            + self.source_id
            + "/intels",
            {
                "name": entity["name"],
                "description": entity["description"],
                "platforms": platforms,
                "contents": entity["pattern"],
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
        intel_document = self._query(
            "put",
            "/plugin/products/threat-response/api/v1/intels/" + intel_id,
            {
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
        openioc = self._query(
            "post",
            "/plugin/products/threat-response/api/v1/intels/quick-add",
            {
                "exact": True,
                "name": name,
                "type": intel_type,
                "text": value,
            },
        )
        if not openioc:
            raise ValueError("Error creating the OpenIOC: " + value)
        payload = {"intelDoc": openioc}
        intel_document = self._query(
            "post",
            "/plugin/products/threat-response/api/v1/sources/"
            + self.source_id
            + "/intels",
            payload,
            "application/xml",
            "openioc",
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
        if intel_type is None or len(value) == 0:
            return None
        openioc = self._query(
            "post",
            "/plugin/products/threat-response/api/v1/intels/quick-add",
            {
                "exact": True,
                "name": name,
                "description": (
                    OpenCTIConnectorHelper.get_attribute_in_extension(
                        "description", entity
                    )
                    if OpenCTIConnectorHelper.get_attribute_in_extension(
                        "description", entity
                    )
                    is not None
                    else ""
                ),
                "type": intel_type,
                "text": value,
            },
        )
        if not openioc:
            raise ValueError("Error creating the OpenIOC: " + value)
        payload = {"intelDoc": openioc}
        intel_document = self._query(
            "put",
            "/plugin/products/threat-response/api/v1/intels/" + intel_id,
            payload,
            "application/xml",
            "openioc",
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
            if (
                OpenCTIConnectorHelper.get_attribute_in_extension("description", entity)
                is not None
            ):
                entry["notes"] = OpenCTIConnectorHelper.get_attribute_in_extension(
                    "description", entity
                )
            if "labels" in entity:
                entry["notes"] = ",".join(entity["labels"])
            reputation_entry = self._query(
                "post",
                "/plugin/products/reputation/v3/reputations/custom/upload?append=true",
                [entry],
            )
            return reputation_entry
        return None

    def delete_intel(self, intel_id):
        self._query(
            "delete",
            "/plugin/products/threat-response/api/v1/intels/?id=" + intel_id,
        )

    def delete_reputation(self, reputation_id):
        self._query(
            "delete",
            "/plugin/products/reputation/v3/reputations/custom/" + reputation_id,
        )

    def deploy_intel(self):
        self._query("post", "/plugin/products/threat-response/api/v1/intel/deploy")

    def trigger_quickscan(self, intel_document_id):
        if self.auto_ondemand_scan:
            for computer_group in self.auto_ondemand_scan_computer_groups:
                self._query(
                    "post",
                    "/plugin/products/threat-response/api/v1/on-demand-scans",
                    {
                        "computerGroupId": int(computer_group),
                        "intelDocId": intel_document_id,
                    },
                )

    def add_label(self, intel_id, label):
        self._query(
            "put",
            "/plugin/products/threat-response/api/v1/intels/"
            + str(intel_id)
            + "/labels",
            {"id": label["id"]},
        )

    def get_labels(self, labels):
        # List labels
        tanium_labels = self._query(
            "get", "/plugin/products/threat-response/api/v1/labels", {"limit": 500}
        )
        tanium_labels_dict = {}
        for tanium_label in tanium_labels:
            tanium_labels_dict[tanium_label["name"].lower()] = tanium_label
        final_labels = []
        for label in labels:
            # Label already exists
            if label in tanium_labels_dict:
                final_labels.append(tanium_labels_dict[label])
            # Create the label
            else:
                created_label = self._query(
                    "post",
                    "/plugin/products/threat-response/api/v1/labels",
                    {
                        "name": label,
                        "description": "Label imported from OpenCTI",
                    },
                )
                final_labels.append(created_label)
        return final_labels
