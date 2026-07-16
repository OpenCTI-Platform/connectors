import json

from jira import JIRA


class JiraConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper

        self.jira_url = self.config.jira.url
        self.jira_ssl_verify = self.config.jira.ssl_verify
        self.jira_login_email = self.config.jira.login_email
        self.jira_api_token = (
            self.config.jira.api_token.get_secret_value()
            if self.config.jira.api_token is not None
            else None
        )
        self.jira_project_key = self.config.jira.project_key
        self.jira_issue_type_name = self.config.jira.issue_type_name

        jira_custom_fields_keys_var = self.config.jira.custom_fields_keys or ""
        self.jira_custom_fields_keys = (
            [key.strip() for key in jira_custom_fields_keys_var.split(",")]
            if jira_custom_fields_keys_var
            else []
        )

        jira_custom_fields_values_var = self.config.jira.custom_fields_values or ""
        self.jira_custom_fields_values = (
            [val.strip() for val in jira_custom_fields_values_var.split(",")]
            if jira_custom_fields_values_var
            else []
        )

        if not self.jira_custom_fields_keys or not self.jira_custom_fields_values:
            self.helper.connector_logger.info(
                "The `jira_custom_fields_keys` or `jira_custom_fields_values` strings are empty. "
                "Lists are initialised with empty defaults. Custom fields will be ignored"
            )
            self.is_custom_fields_ignored = True
        elif len(self.jira_custom_fields_keys) != len(self.jira_custom_fields_values):
            self.helper.connector_logger.error(
                "The lengths between the `jira_custom_fields_keys` and `jira_custom_fields_values` lists do not match. "
                "Make sure that each key has a corresponding value. Custom fields will be ignored",
                {
                    "len_jira_custom_fields_keys": len(self.jira_custom_fields_keys),
                    "jira_custom_fields_keys": self.jira_custom_fields_keys,
                    "len_jira_custom_fields_values": len(
                        self.jira_custom_fields_values
                    ),
                    "jira_custom_fields_values": self.jira_custom_fields_values,
                },
            )
            self.is_custom_fields_ignored = True
        else:
            self.is_custom_fields_ignored = False

        self.jira_client = JIRA(
            server=self.jira_url,
            basic_auth=(self.jira_login_email, self.jira_api_token),
            options={"verify": self.jira_ssl_verify},
        )

    def check_stream_id(self):
        """
        In case of stream_id configuration is missing, raise ValueError
        """
        if (
            not self.helper.connect_live_stream_id
            or self.helper.connect_live_stream_id.lower() == "changeme"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
        except Exception as exc:
            raise ValueError("Cannot process the message") from exc

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
                    if not self.is_custom_fields_ignored:
                        for idx, key in enumerate(self.jira_custom_fields_keys):
                            issue[key] = self.jira_custom_fields_values[idx]
                    self.jira_client.create_issue(fields=issue)
                return

            if msg.event == "update":
                return
            elif msg.event == "delete":
                return
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.check_stream_id()
        self.helper.listen_stream(self._process_message)

    # Backward-compatible entrypoint name (kept to avoid breaking existing usage)
    def start(self):
        self.run()
