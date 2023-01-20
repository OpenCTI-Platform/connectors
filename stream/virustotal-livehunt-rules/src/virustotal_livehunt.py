import ast
import json
import os
import queue
from time import sleep

import yaml
from client import VirusTotalClient
from pycti import OpenCTIConnectorHelper, get_config_variable

q = queue.Queue()


class VTConnector:

    _SOURCE_NAME = "VirusTotal"
    _API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        # Initialize parameters and OpenCTI helper
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        # config_file_path = "./config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)
        self.token = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_TOKEN", ["virustotal_livehunt", "token"], config
        )
        self.notification_emails = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATION_EMAILS",
            ["virustotal_livehunt", "notification_emails"],
            config,
        )
        self.shared_owners = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_SHARED_OWNERS",
            ["virustotal_livehunt", "shared_owners"],
            config,
        )

        # Making  a list
        if self.shared_owners:
            self.shared_owners = ast.literal_eval(self.shared_owners)

        self.helper.log_debug("Printing email list" + str(self.notification_emails))
        self.helper.log_debug(
            "Printing email type list" + str(type(self.notification_emails))
        )

        self.client = VirusTotalClient(self.helper, self._API_URL, self.token)

        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing Live Stream ID")

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]

        except:
            raise ValueError("Cannot process the message: " + str(msg))

        # Handle creation
        if (
            msg.event == "create"
            and data.get("type") == "indicator"
            and data.get("pattern_type") == "yara"
        ):

            extensions_data = data.get("extensions")
            for each_extenstion in extensions_data:
                self.helper.log_info("Handle create message")
                try:
                    detection_value = (
                        data.get("extensions").get(each_extenstion).get("detection")
                    )
                    if detection_value == True:

                        rule = data.get("pattern")
                        name = data.get("name")
                        response = self.client.create_vt_livehunt_rule(
                            name, rule, self.notification_emails
                        )

                        if response.status_code == 200:

                            response_data = response.json()
                            rule_id_created = response_data.get("data").get("id")

                            if self.shared_owners:
                                for each_owner in self.shared_owners:
                                    owner_creation = self.client.add_shared_owners(
                                        rule_id_created, each_owner
                                    )
                                    self.helper.log_debug(
                                        "[CREATE] Adding owner to rule =  {"
                                        + str(owner_creation)
                                        + "}"
                                    )

                            self.helper.log_info(
                                "[CREATE] Rule created rule_id =  {"
                                + str(rule_id_created)
                                + "}"
                            )

                            return rule_id_created

                        elif response.status_code == 400:
                            self.helper.log_info(
                                "[CREATE] Rule has an incorrect format :  {"
                                + str(rule)
                                + "}"
                            )

                        else:
                            self.helper.log_error(
                                "[CREATE] Failed to create the VT livehunt :  {"
                                + str(response.status_code)
                                + "}"
                            )

                    else:
                        pass
                except:
                    pass

        # Handle Update
        if (
            msg.event == "update"
            and data.get("type") == "indicator"
            and data.get("pattern_type") == "yara"
        ):

            self.helper.log_info("Handle update to create message")

            # Getting Rule
            rule = data.get("pattern")
            # Getting OpenCTI Name of the indicator
            name = data.get("name")
            # Cheching if the Rule already exists in VT
            rule_id = self.client.get_vt_livehunt_rule_id(name)

            self.helper.log_debug("[Update] RULE ID {" + str(rule_id) + "}")

            extensions_data = data.get("extensions")
            for each_extenstion in extensions_data:

                # try:
                detection_value = (
                    data.get("extensions").get(each_extenstion).get("detection")
                )

                self.helper.log_debug(
                    "Detection value "
                    + str(detection_value)
                    + "Rule value "
                    + str(rule_id)
                )

                if detection_value == True and rule_id == False:
                    self.helper.log_debug(
                        "Handle Update message detection True rule_id False"
                    )
                    response = self.client.create_vt_livehunt_rule(
                        name, rule, self.notification_emails
                    )
                    if response.status_code == 200:

                        response_data = response.json()
                        rule_id_created = response_data.get("data").get("id")

                        if self.shared_owners:
                            for each_owner in self.shared_owners:
                                owner_creation = self.client.add_shared_owners(
                                    rule_id_created, each_owner
                                )
                                self.helper.log_debug(
                                    "[CREATE] Adding owner to rule =  {"
                                    + str(owner_creation)
                                    + "}"
                                )

                        self.helper.log_info(
                            "[CREATE] Rule created rule_id =  {"
                            + str(rule_id_created)
                            + "}"
                        )

                        return rule_id_created

                    elif response.status_code == 400:
                        self.helper.log_info(
                            "[CREATE] Rule has an incorrect format :  {"
                            + str(rule)
                            + "}"
                        )

                    else:
                        self.helper.log_error(
                            "[CREATE] Failed to create the VT livehunt :  {"
                            + str(response.status_code)
                            + "}"
                        )

                elif detection_value == True and rule_id != False:
                    self.helper.log_debug(
                        "Handle Update message detection True rule_id True"
                    )

                    self.client.delete_vt_livehunt_rule(rule_id)
                    self.helper.log_info("[Update] Deleting rule to recreate{" + "}")

                    response = self.client.create_vt_livehunt_rule(
                        name, rule, self.notification_emails
                    )
                    if response.status_code == 200:

                        response_data = response.json()
                        rule_id_created = response_data.get("data").get("id")

                        if self.shared_owners:
                            for each_owner in self.shared_owners:
                                owner_creation = self.client.add_shared_owners(
                                    rule_id_created, each_owner
                                )
                                self.helper.log_debug(
                                    "[CREATE] Adding owner to rule =  {"
                                    + str(owner_creation)
                                    + "}"
                                )

                        self.helper.log_info(
                            "[CREATE] Rule created rule_id =  {"
                            + str(rule_id_created)
                            + "}"
                        )
                        sleep(5)
                        return rule_id_created

                    elif response.status_code == 400:
                        self.helper.log_info(
                            "[CREATE] Rule has an incorrect format :  {"
                            + str(rule)
                            + "}"
                        )

                    else:
                        self.helper.log_error(
                            "[CREATE] Failed to create the VT livehunt :  {"
                            + str(response.status_code)
                            + "}"
                        )

                elif detection_value == False and rule_id != False:
                    self.helper.log_info(
                        "Handle Update message detection False rule_id True"
                    )
                    delete_response = self.client.delete_vt_livehunt_rule(rule_id)
                    self.helper.log_info(
                        "[Update] Deleting rule {" + str(delete_response) + "}"
                    )
                    return delete_response

                else:
                    pass

                # except:
                #     pass

        # Handle delete
        elif (
            msg.event == "delete"
            and data.get("type") == "indicator"
            and data.get("pattern_type") == "yara"
        ):

            self.helper.log_info("Handle delete message")

            name = data.get("name")
            rule_id = self.client.get_vt_livehunt_rule_id(name)
            if rule_id == False:
                pass
            else:
                delete_response = self.client.delete_vt_livehunt_rule(rule_id)
                self.helper.log_info(
                    "[Delete] Deleting rule {" + str(delete_response) + "}"
                )
                return delete_response

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    VTInstance = VTConnector()
    VTInstance.start()
