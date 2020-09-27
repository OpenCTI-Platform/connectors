import os
import yaml
import json
import requests

from stix2slider import slide_string
from stix2slider.options import initialize_options
from pycti import OpenCTIConnectorHelper, get_config_variable


class TaniumConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.tanium_url = get_config_variable("TANIUM_URL", ["tanium", "url"], config)
        self.tanium_login = get_config_variable(
            "TANIUM_LOGIN", ["tanium", "login"], config
        )
        self.tanium_password = get_config_variable(
            "TANIUM_PASSWORD", ["tanium", "password"], config
        )
        self.tanium_indicator_types = get_config_variable(
            "TANIUM_INDICATOR_TYPES", ["tanium", "indicator_types"], config
        ).split(",")
        self.tanium_observable_types = get_config_variable(
            "TANIUM_OBSERVABLE_TYPES", ["tanium", "observable_types"], config
        ).split(",")
        self.tanium_import_label = get_config_variable(
            "TANIUM_IMPORT_LABEL",
            ["tanium", "import_label"],
            config,
        )

        # Variables
        self.session = None

        # Open a session
        self._get_session()

    def _get_session(self):
        payload = {
            "username": self.tanium_login,
            "password": self.tanium_password,
        }
        r = requests.post(self.tanium_url + "/api/v2/session/login", json=payload)
        if r.status_code == 200:
            result = r.json()
            self.session = result["data"]["session"]
        else:
            raise ValueError("Cannot login to the Tanium API")

    def _query(
        self,
        method,
        uri,
        payload,
        content_type="application/json",
        type=None,
        retry=False,
    ):
        headers = {"session": self.session, "content-type": content_type, "type": type}
        if method == "get":
            r = requests.get(self.tanium_url + uri, headers=headers, params=payload)
        elif method == "post":
            if type is not None:
                r = requests.post(
                    self.tanium_url + uri, headers=headers, data=payload["intelDoc"]
                )
            else:
                r = requests.post(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "put":
            r = requests.put(self.tanium_url + uri, headers=headers, json=payload)
        elif method == "patch":
            r = requests.patch(self.tanium_url + uri, headers=headers, json=payload)
        else:
            raise ValueError("Unspported method")
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 401 and not retry:
            self._get_session()
            self._query(method, uri, payload, content_type, type, True)
        elif r.status_code == 401:
            raise ValueError("Query failed, permission denied")
        else:
            print(r.text)

    def _get_labels(self, labels):
        # List labels
        tanium_labels = self._query(
            "get", "/plugin/products/detect3/api/v1/labels", {"limit": 500}
        )
        tanium_labels_dict = {}
        for tanium_label in tanium_labels:
            tanium_labels_dict[tanium_label["name"]] = tanium_label
        final_labels = []
        for label in labels:
            # Label already exists
            if label["value"] in tanium_labels_dict:
                final_labels.append(tanium_labels_dict[label["value"]])
            # Create the label
            else:
                created_label = self._query(
                    "post",
                    "/plugin/products/detect3/api/v1/labels",
                    {
                        "name": label["value"],
                        "description": "Label imported from OpenCTI",
                    },
                )
                final_labels.append(created_label)
        return final_labels

    def _check_exists(self, standard_id):
        response = self._query(
            "get",
            "/plugin/products/detect3/api/v1/intels",
            {"description": standard_id},
        )
        print(response)
        if response and response["intelDocs"] and len(response["intelDocs"]) > 0:
            return response["intelDocs"][0]
        else:
            return None

    def _process_message(self, msg):
        data = json.loads(msg.data)
        entity_type = data["data"]["type"]
        if (
            entity_type != "indicator"
            and entity_type not in self.tanium_observable_types
        ):
            return

        # Handle creation
        intel_document = None
        entity = None
        if msg.event == "create":
            if (
                "labels" not in data["data"]
                or self.tanium_import_label not in data["data"]["labels"]
            ):
                return
            if entity_type == "indicator":
                if data["data"]["pattern_type"] == "stix":
                    entity = self.helper.api.indicator.read(id=data["data"]["id"])
                    if entity is None:
                        return
                    intel_document = self._check_exists(entity["standard_id"])
                    if not intel_document:
                        entity["description"] = entity["standard_id"]
                        stix2_bundle = self.helper.api.stix2.export_entity(
                            entity["entity_type"], entity["id"], "simple", None, True
                        )
                        initialize_options()
                        try:
                            stix_indicator = slide_string(stix2_bundle)
                        except:
                            self.helper.log_error(
                                "Cannot convert the indicator to STIX 1"
                            )
                            return
                        payload = {"intelDoc": stix_indicator}
                        intel_document = self._query(
                            "post",
                            "/plugin/products/detect3/api/v1/intels",
                            payload,
                            "application/xml",
                            "stix",
                        )

        if intel_document is not None and entity is not None:
            external_reference = self.helper.api.external_reference.create(
                source_name="Tanium",
                url=self.tanium_url
                + "/#/thr_workbench/intel/"
                + str(intel_document["id"]),
                external_id=str(intel_document["id"]),
                description="Intel document within the Tanium platform.",
            )
            self.helper.api.stix_domain_object.add_external_reference(
                id=entity["id"], external_reference_id=external_reference["id"]
            )
            if len(entity["objectLabel"]) > 0:
                labels = self._get_labels(entity["objectLabel"])
                for label in labels:
                    self._query(
                        "put",
                        "/plugin/products/detect3/api/v1/intels/"
                        + str(intel_document["id"])
                        + "/labels",
                        {"id": label["id"]},
                    )

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    TaniumInstance = TaniumConnector()
    TaniumInstance.start()
