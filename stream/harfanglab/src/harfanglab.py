import os.path

import yaml
import json
import time
import sys
import requests

from pycti import OpenCTIConnectorHelper, get_config_variable
import logging


class HarfangLabConnector:
    def __init__(self):
        # Initialize parameters and OpenCTI helper
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Initialiaze the Harfang Lab API
        self.harfanglab_url = get_config_variable("HARFANGLAB_URL", ["harfanglab", "url"], config)

        # TODO is basic auth needed/used?
        self.harfanglab_ssl_verify = get_config_variable(
            "HARFLANGLAB_SSL_VERIFY", ["harfanglab", "ssl_verify"], config, False, True
        )
        self.harfanglab_token = get_config_variable(
            "HARFLANGLAB_TOKEN", ["harfanglab", "token"], config
        )
        self.harfanglab_login = get_config_variable(
            "HARFLANGLAB_LOGIN", ["harfanglab", "login"], config
        )
        self.harfanglab_password = get_config_variable(
            "HARFLANGLAB_PASSWORD", ["harfanglab", "password"], config
        )
        self.api_url = (
                self.harfanglab_url
                + "/api/data/threat_intelligence"
        )
        self.headers = {
            "Accept": "application/json",
            "Authorization": "Token " + self.harfanglab_token
        }
        self.harfanglab_source_list_name = get_config_variable(
            "HARFLANGLAB_SOURCE_LIST_NAME", ["harfanglab", "source_list_name"], config
        )
        self.source_list = {
            "name": self.harfanglab_source_list_name,
            "enabled": True,
        }

        # Yara pattern
        response = requests.get(
            self.api_url + '/YaraSource/',
            headers=self.headers,
            params={'search': self.harfanglab_source_list_name}
        )
        list_of_yara_sources = json.loads(response.content)['results']

        element = next((x for x in list_of_yara_sources if x["name"] == self.harfanglab_source_list_name), None)
        if element is None:
            # create list
            response = requests.post(
                self.api_url + '/YaraSource/',
                headers=self.headers,
                json=self.source_list
            )
            self.harfanglab_yara_list_id = json.loads(response.content)['id']
        else:
            self.harfanglab_yara_list_id = element['id']

        # Sigma pattern
        response = requests.get(
            self.api_url + '/SigmaSource/',
            headers=self.headers,
            params={'search': self.harfanglab_source_list_name}
        )
        list_of_sigma_sources = json.loads(response.content)['results']

        element = next((x for x in list_of_sigma_sources if x["name"] == self.harfanglab_source_list_name), None)
        if element is None:
            # create list
            response = requests.post(
                self.api_url + '/SigmaSource/',
                headers=self.headers,
                json=self.source_list
            )
            self.harfanglab_sigma_list_id = json.loads(response.content)['id']
        else:
            self.harfanglab_sigma_list_id = element['id']

    def _process_message(self, msg):
        # _process_message
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message")
        # Handle creation
        self.helper.log_info(f'Processing the object {data["id"]}')

        if msg.event == "create":
            # TODO YARA, Sigma and IoC
            # TODO Only revoked=false
            if data["type"] == "indicator" and data["revoked"] is False and OpenCTIConnectorHelper.get_attribute_in_extension("detection", data) is True:
                if data["pattern_type"] == "yara":
                    self.helper.log_info(
                        "[CREATE] Processing indicator {"
                        + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                        + "}"
                    )
                    yara_indicator = {
                        "content": data["pattern"],
                        "enabled": True,
                        "hl_local_testing_status": "in_progress",
                        "hl_status": "stable",
                        "name": data["name"],
                        "source_id": self.harfanglab_yara_list_id
                    }
                    response = requests.post(
                        self.api_url + '/YaraFile/',
                        headers=self.headers,
                        json=yara_indicator
                    )
                    #TODO handle case where status contains many elements
                    if json.loads(response.content)['status'][0]['status'] is False:
                        self.helper.log_error(f"Error = {json.loads(response.content)['status'][0]['content']}")
                    else:
                        self.helper.log_info(f'Indicator YARA created = {response}')

                elif data["pattern_type"] == "sigma":
                    self.helper.log_info(
                        "[CREATE] Processing indicator {"
                        + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                        + "}"
                    )
                    sigma_indicator = {
                        "block_on_agent": True,
                        "content": data["pattern"],
                        "enabled": True,
                        "hl_local_testing_status": "in_progress",
                        "hl_status": "stable",
                        "name": data["name"],
                        "source_id": self.harfanglab_sigma_list_id
                    }
                    response = requests.post(
                        self.api_url + '/SigmaRule/',
                        headers=self.headers,
                        json=sigma_indicator
                    )
                    if json.loads(response.content)['status'][0]['status'] is False:
                        self.helper.log_error(f"[CREATE] Error = {json.loads(response.content)['status'][0]['content']}")
                    else:
                        self.helper.log_info(f'Indicator SIGMA created = {response}')

                # elif data["pattern_type"] == "stix":
                #     # TODO check if it's the right name to get the type?
                #     if data["x_opencti_main_observable_type"] in ["StixFile", "Domain-Name", "IPv4-Addr", "IPv6-Addr", "Url"]:
                #         # TODO Exctract data from pattern
                #         data["pattern"]

            return

        # Handle update
        if msg.event == "update":
            if data["type"] == "indicator":
                if data["pattern_type"] == "yara":
                    self.helper.log_info(
                        "[UPDATE] Processing indicator {"
                        + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                        + "}"
                    )

                    yara_name_indicator_reverse_patch = json.loads(msg.data)['context']['reverse_patch'][0]['value']
                    response_yara_name_indicator = requests.get(
                        self.api_url + f'/YaraFile/?search={yara_name_indicator_reverse_patch}',
                        headers=self.headers,
                    )

                    response_yara_content = response_yara_name_indicator.content
                    response_yara_content_count = json.loads(response_yara_content)['count']
                    response_yara_status_code = response_yara_name_indicator.status_code

                    if response_yara_status_code != 200:
                        msg_log = f'[UPDATE] The request returned code {response_yara_status_code}'
                        self.helper.log_error(msg_log),
                    elif response_yara_content_count == 0:
                        msg_log = f'[UPDATE] The searched name of the Yara indicator ({yara_name_indicator_reverse_patch}) does not exist in HarfangLab'
                        self.helper.log_error(msg_log),
                    else:
                        response_yara_content_id = json.loads(response_yara_content)['results'][0]['id']

                        yara_indicator = {
                            "name": data["name"],
                            "content": data["pattern"],
                            "source_id": self.harfanglab_yara_list_id
                        }

                        response = requests.put(
                            self.api_url + f'/YaraFile/{response_yara_content_id}/',
                            headers=self.headers,
                            json=yara_indicator
                        )
                        # TODO handle case where status contains many elements
                        if response.status_code != 200:
                            msg_log = f"[UPDATE] Error {response.status_code} = {json.loads(response.content)['detail']}"
                            self.helper.log_error(msg_log)
                        else:
                            self.helper.log_info(f'Indicator YARA updated')

                if data["pattern_type"] == "sigma":
                    self.helper.log_info(
                        "[UPDATE] Processing indicator {"
                        + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                        + "}"
                    )

                    sigma_name_indicator_reverse_patch = json.loads(msg.data)['context']['reverse_patch'][0]['value']
                    response_sigma_name_indicator = requests.get(
                        self.api_url + f'/SigmaRule/?search={sigma_name_indicator_reverse_patch}',
                        headers=self.headers,
                        )

                    response_sigma_content = response_sigma_name_indicator.content
                    response_sigma_content_count = json.loads(response_sigma_content)['count']
                    response_sigma_status_code = response_sigma_name_indicator.status_code

                    if response_sigma_status_code != 200:
                        msg_log = f'[UPDATE] The request returned code {response_sigma_status_code}'
                        self.helper.log_error(msg_log),
                    elif response_sigma_content_count == 0:
                        msg_log = f'[UPDATE] The searched name of the Sigma indicator ({sigma_name_indicator_reverse_patch}) does not exist in HarfangLab'
                        self.helper.log_error(msg_log),
                    else:
                        response_sigma_content_id = json.loads(response_sigma_content)['results'][0]['id']

                        sigma_indicator = {
                            "name": data["name"],
                            "content": data["pattern"],
                            "source_id": self.harfanglab_sigma_list_id
                        }

                        response = requests.put(
                            self.api_url + f'/SigmaRule/{response_sigma_content_id}/',
                            headers=self.headers,
                            json=sigma_indicator
                        )
                        # TODO handle case where status contains many elements
                        if response.status_code != 200:
                            msg = f"[UPDATE] Error {response.status_code} = {json.loads(response.content)['detail']}"
                            self.helper.log_error(msg)
                        else:
                            self.helper.log_info(f'Indicator SIGMA updated')

            return
        if msg.event == "delete":
            return




    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    try:
        HarfangLabInstance = HarfangLabConnector()
        HarfangLabInstance.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
