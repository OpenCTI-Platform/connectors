import json
import os
import sys
import time

import yaml
from jira import JIRA
from pycti import OpenCTIConnectorHelper, get_config_variable


class TaxiiPostConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.jira_url = get_config_variable(
            "JIRA_URL",
            ["jira", "url"],
            config,
        )
        self.jira_ssl_verify = get_config_variable(
            "JIRA_SSL_VERIFY", ["jira", "ssl_verify"], config, default=True
        )
        self.jira_login_email = get_config_variable(
            "JIRA_LOGIN_EMAIL",
            ["jira", "login_email"],
            config,
        )
        self.jira_api_token = get_config_variable(
            "JIRA_API_TOKEN", ["jira", "api_token"], config
        )
        self.jira_project_key = get_config_variable(
            "JIRA_PROJECT_KEY", ["jira", "project_key"], config
        )
        self.jira_issue_type_name = get_config_variable(
            "JIRA_ISSUE_TYPE_NAME", ["jira", "issue_type_name"], config
        )
        self.jira_custom_fields_keys = get_config_variable(
            "JIRA_CUSTOM_FIELDS_KEYS",
            ["jira", "custom_fields_keys"],
            config,
            default="",
        ).split(",")
        self.jira_custom_fields_values = get_config_variable(
            "JIRA_CUSTOM_FIELDS_VALUES",
            ["jira", "custom_fields_values"],
            config,
            default="",
        ).split(",")
        self.jira_client = JIRA(
            server=self.jira_url,
            basic_auth=(self.jira_login_email, self.jira_api_token),
        )

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message")
        self.helper.log_info("Processing the object " + data["id"])
        try:
            if msg.event == "create":
                if data["type"] in [
                    "incident",
                    "report",
                    "case-incident",
                    "case-rfi",
                    "case-rft",
                    "grouping",
                ]:
                    issue = {
                        "project": {"key": self.jira_project_key},
                        "summary": data["name"],
                        "description": data.get("description", ""),
                        "labels": data.get("labels", []),
                        "issuetype": {"name": self.jira_issue_type_name},
                    }
                    for idx, key in enumerate(self.jira_custom_fields_keys):
                        issue[key] = self.jira_custom_fields_values[idx]
                    self.jira_client.create_issue(fields=issue)
                return
            # Handle update
            if msg.event == "update":
                # Not supported yet
                return
            # Handle delete
            elif msg.event == "delete":
                # Not supported yet
                return

        except Exception as e:
            self.helper.log_error(str(e))

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    try:
        connector = TaxiiPostConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
