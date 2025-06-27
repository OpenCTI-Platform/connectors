# -*- coding: utf-8 -*-
"""Virustotal client module."""
import ast
import json

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class VirusTotalClient:
    """VirusTotal client."""

    def __init__(
        self, helper: OpenCTIConnectorHelper, base_url: str, token: str
    ) -> None:
        """Initialize Virustotal client."""
        self.helper = helper
        # Drop the ending slash if present.
        self.url = base_url[:-1] if base_url[-1] == "/" else base_url
        self.helper.log_debug(f"[VirusTotal] URL: {self.url}")
        self.headers = {
            "x-apikey": token,
            "accept": "application/json",
            "content-type": "application/json",
        }

    def _query(self, method, url, payload=None):
        """
        Execute a query to the Virustotal api.

        The authentication is done using the headers with the token given
        during the creation of the client.

        Retries are done if the query fails.

        Parameters
        ----------
        url : str
            Url to query.

        Returns
        -------
        JSON or None
            The result of the query, as JSON or None in case of failure.
        """
        # Configure the adapter for the retry strategy.
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        response = None
        try:
            response = http.request(method, url, headers=self.headers, data=payload)
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            self.helper.log_error(f"[VirusTotal] Http error: {errh}")
        except requests.exceptions.ConnectionError as errc:
            self.helper.log_error(f"[VirusTotal] Error connecting: {errc}")
        except requests.exceptions.Timeout as errt:
            self.helper.log_error(f"[VirusTotal] Timeout error: {errt}")
        except requests.exceptions.RequestException as err:
            self.helper.log_error(f"[VirusTotal] Something else happened: {err}")
        except Exception as err:
            self.helper.log_error(f"[VirusTotal] Unknown error {err}")
        try:
            # if method == "DELETE":
            #     self.helper.log_debug(f"[VirusTotal] data deleted: {response}")
            #     return response
            # else:
            self.helper.log_debug(f"[VirusTotal] data retrieved: {response}")
            return response
        except json.JSONDecodeError as err:
            self.helper.log_error(
                f"[VirusTotal] Error decoding the json: {err} - {response.text}"
            )
            return None

    def get_vt_livehunt_rule_id(self, name):
        """
        Retrieve existing livehunt rule IDs based on a name.

        Parameters
        ----------
        name : str
            Name of the rule.

        Returns
        -------
        dict
            File object, seehttps://developers.virustotal.com/reference/livehunt.
        """
        url = f"{self.url}/intelligence/hunting_rulesets"
        data_from_query = self._query("GET", url)

        # try:
        data = data_from_query.json()

        self.helper.log_debug("[DATA] " + str(data))

        rules = data.get("data")
        self.helper.log_debug("[RULES] " + str(rules))
        for each in rules:
            try:
                rule_name = each.get("attributes").get("name")
                self.helper.log_debug("[RULE NAME] " + str(rule_name))
                if rule_name == name:
                    self.helper.log_debug("[NAME] " + str(rule_name))
                    rule_id = each.get("id")
                    self.helper.log_debug("[RULE ID] " + str(rule_id))
                    message = rule_id
                else:
                    pass
            except Exception as err:
                self.helper.log_error(f"[VirusTotal]  Getting name for each rule {err}")
        try:
            return message
        except:
            self.helper.log_debug("Not rule ID found by the name " + str(name))
            return False

    def delete_vt_livehunt_rule(self, rule_id):
        """
        Delete existing livehunt rule ID based on a rule ID.

        Parameters
        ----------
        ID : str
            ID of the rule.

        Returns
        -------
        dict
            File object, seehttps://developers.virustotal.com/reference/livehunt.
        """
        self.helper.log_debug("[DELETE RULE ID] " + str(rule_id))
        self.helper.log_debug("[DELETE TYPE RULE ID] " + str(type(rule_id)))
        url = f"{self.url}/intelligence/hunting_rulesets/{rule_id}"
        return self._query("DELETE", url)

    def create_vt_livehunt_rule(self, name, rule, notification_emails):
        """
        Create livehunt rule.

        Parameters
        ----------
        name : str
            Name of the rule.
        rule : str
            Yara Rule.
        notification_emails : list or str
            List of the email to notify.

        Returns
        -------
        dict
            File object, seehttps://developers.virustotal.com/reference/livehunt.
        """
        # Handle notification_emails format
        try:
            if isinstance(notification_emails, str):
                # Try to safely evaluate the string as a Python literal
                emails = ast.literal_eval(notification_emails.replace("'", '"'))
            else:
                emails = notification_emails
            
            if not isinstance(emails, list):
                emails = [emails]  # Convert single email to list
        except Exception as e:
            self.helper.log_error(f"Error processing notification emails: {str(e)}")
            self.helper.log_error(f"Raw notification_emails value: {notification_emails}")
            emails = []

        self.helper.log_debug(f"Processed notification emails for rule {name}: {emails}")

        # If new_files_only is enabled, modify the rule to include new_file condition
        if hasattr(self, 'new_files_only') and self.new_files_only:
            try:
                # Parse the rule to find the condition section
                rule_lines = rule.split('\n')
                condition_start = -1
                for i, line in enumerate(rule_lines):
                    if line.strip().startswith('condition:'):
                        condition_start = i
                        break
                
                if condition_start != -1:
                    # Add new_file to the condition
                    condition_line = rule_lines[condition_start].strip()
                    if condition_line == 'condition:':
                        # If condition is on its own line
                        rule_lines.insert(condition_start + 1, '    new_file and')
                    else:
                        # If condition is inline
                        rest_of_condition = condition_line[len('condition:'):].strip()
                        rule_lines[condition_start] = f'condition: new_file and {rest_of_condition}'
                    
                    rule = '\n'.join(rule_lines)
                    self.helper.log_debug(f"Modified rule with new_file condition for {name}")
                else:
                    self.helper.log_error(f"Could not find condition section in rule {name}")
            except Exception as e:
                self.helper.log_error(f"Error modifying rule with new_file condition: {str(e)}")

        try:
            payload = json.dumps(
                {
                    "data": {
                        "type": "hunting_ruleset",
                        "attributes": {
                            "name": name,
                            "enabled": True,
                            "limit": 100,
                            "rules": rule,
                            "notification_emails": emails,
                        },
                    }
                }
            )
            self.helper.log_debug(f"Sending rule creation request for {name}")
            return self._query("POST", url=f"{self.url}/intelligence/hunting_rulesets", payload=payload)
        except Exception as e:
            self.helper.log_error(f"Error creating rule {name}: {str(e)}")
            return None

    def add_shared_owners(self, rule_id, shared_owners):
        """
        Add owners to a rule.

        Parameters
        ----------
        rule_id : str
            Rule ID to add owners.
        shared_owners : str
            User ID of the owner.

        Returns
        -------
        dict
            File object, seehttps://developers.virustotal.com/reference/livehunt.
        """
        self.helper.log_debug("Owner to be added " + str(shared_owners))

        self.helper.log_debug("Owner to be added in rule ID  " + str(rule_id))

        payload = json.dumps({"data": [{"type": "user", "id": shared_owners}]})

        self.helper.log_debug("Payload to add owner to rule  " + str(payload))

        url = (
            f"{self.url}/intelligence/hunting_rulesets/{rule_id}/relationships/editors"
        )
        return self._query("POST", url, payload)

    def list_all_rules(self):
        """
        List all livehunt rules.

        Returns
        -------
        dict
            All livehunt rules
        """
        url = f"{self.url}/intelligence/hunting_rulesets"
        response = self._query("GET", url)
        if response and response.status_code == 200:
            return response.json()
        return None
