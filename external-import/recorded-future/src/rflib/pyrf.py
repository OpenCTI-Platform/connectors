from datetime import datetime, timedelta, timezone

import requests
from pycti import OpenCTIConnectorHelper


class RecordedFutureApiError(Exception):
    """Wrap exceptions emitted in RecordedFutureApiClient"""


class PlaybookAlertSummary:
    def __init__(self, playbook_alert_id, priority, created, category, title):
        self.playbook_alert_id = playbook_alert_id
        self.priority = priority
        self.created = created
        self.category = category
        self.title = title


class PlaybookId:
    def __init__(
        self,
        playbook_alert_id,
        playbook_alert_status,
        playbook_alert_priority,
        playbook_alert_date,
        playbook_alert_category,
        playbook_alert_title,
    ):
        self.playbook_alert_id = playbook_alert_id
        self.playbook_alert_status = playbook_alert_status
        self.playbook_alert_priority = playbook_alert_priority
        self.playbook_alert_date = playbook_alert_date
        self.playbook_alert_category = playbook_alert_category
        self.playbook_alert_title = playbook_alert_title


class PrioritiedRule:
    def __init__(self, rule_id, rule_name, rule_intelligence_goal):
        self.rule_id = rule_id
        self.rule_name = rule_name.replace("'", "'")
        self.rule_intelligence_goal = rule_intelligence_goal
        if self.rule_name[-1] == " ":
            self.rule_name = self.rule_name[:-1]
        if self.rule_name[0] == " ":
            self.rule_name = self.rule_name[:0]


class Alert:
    def __init__(
        self,
        alert_id,
        alert_url,
        alert_date,
        alert_title,
        alert_ai_insight,
        alert_rf_rule,
        alert_hits,
    ):
        self.alert_id = alert_id
        self.alert_url = alert_url
        self.alert_date = alert_date
        self.alert_title = alert_title
        self.alert_ai_insight = alert_ai_insight
        self.alert_rf_rule = alert_rf_rule
        self.alert_hits = alert_hits


class RecordedFutureApiClient:
    def __init__(
        self,
        x_rf_token: str,
        helper: OpenCTIConnectorHelper,
        base_url: str = "https://api.recordedfuture.com/",
        priority_alerts_only: bool = False,
    ):
        self.x_rf_token = x_rf_token
        self.base_url = base_url
        self.priorited_rules: list[PrioritiedRule] = []
        self.unfound_rf_rules_in_vocabularies: list[PrioritiedRule] = []
        self.playbook_alerts: list[PlaybookId] = []
        self.helper = helper
        self.playbook_alerts_summaries: list[PlaybookAlertSummary] = []
        self.priority_alerts_only = priority_alerts_only

    def _header_response_control(self, response):
        # If there is an unexpected content type, log the error
        rf_content_type = response.headers.get("Content-Type")

        if rf_content_type != "application/json":
            raise RecordedFutureApiError(
                "Unexpected Content-Type from RecordedFuture's API: ",
                {"content-type": rf_content_type},
            )

    def _data_control(self, data, expected_status_message=None):
        """
        Validates the integrity and expected structure of the response data from the Recorded Future API.

        :param data: dict, the response data to be validated. This should be a dictionary returned from the API.
        :param expected_status_message: str, an optional parameter specifying the expected status message
                                         to verify against the response. Defaults to None.
        :return: None, this method does not return any value but logs errors for invalid or unexpected data.

        Validation Steps:
            1. Checks if the response contains a "data" field. Logs an error if it is missing.
            2. Ensures the response is a dictionary. Logs an error if the response is of a different type.
            3. If `expected_status_message` is provided:
               - Verifies that the response contains a "status" field. Logs an error if absent.
               - Checks if the "status_code" is "Ok". Logs an error if it is not.
               - Confirms that the "status_message" matches the expected message. Logs an error if it doesn't.

        Error Handling:
            - Logs specific error messages using `self.helper.connector_logger.error` when validation fails.
            - Errors include missing fields, incorrect status codes, or mismatched status messages.
        """

        # If the response is not a dictionary, log the error
        if not isinstance(data, dict):
            self.helper.connector_logger.error("Response data is not a dictionary")
            return

        # If the response doesn't contain data, log the error
        if not data.get("data"):
            self.helper.connector_logger.error(
                "No rules returned from Recorded Future API"
            )
            return

        if expected_status_message is not None:
            # If the response does not contain mandatory fields, log the error
            if "status" not in data:
                self.helper.connector_logger.error(
                    "Response does not contain mandatory status field",
                    {"mandatory_field": "status"},
                )
                return

            # If the response status_code is not Ok, log the error
            if data.get("status", {}).get("status_code", "").lower() != "ok":
                self.helper.connector_logger.error("Response status_code is not Ok")
                return

            # If the alert search is unsuccessful, log the error
            if data["status"]["status_message"] != f"{expected_status_message}":
                self.helper.connector_logger.error(
                    "Process unsuccessful",
                    {"status_message": data["status"]["status_message"]},
                )
                return

    def _raw_get_alerts(
        self,
        rule: PrioritiedRule,
        triggered_since: datetime,
        triggered_until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        """
        Get search alerts raw data for a given rule and time range.
        :param rule: The rule to get alerts for.
        :param since: The date from which to get alerts.
        :param until: The date until which to get alerts (optional).
        :param limit: The maximum number of alerts to retrieve per request (default is 100).
        :param offset: The offset for pagination (default is 0).
        :return: Search alerts raw dictionary.
        """
        try:
            triggered_since_iso = triggered_since.isoformat().replace("+00:00", "Z")
            triggered_until_iso = (
                triggered_until.isoformat().replace("+00:00", "Z")
                if triggered_until
                else ""
            )

            response = requests.get(
                self.base_url + "v3/alerts",
                headers={
                    "X-RFToken": self.x_rf_token,
                    "accept": "application/json",
                },
                params={
                    "alertRule": rule.rule_id,
                    "triggered": f"[{triggered_since_iso},{triggered_until_iso}]",
                    "limit": limit,
                    "from": offset,
                },
            )
            response.raise_for_status()

            data = response.json()

            self.helper.connector_logger.debug(
                "Alert(s) found on Recorded Future API",
                {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.rule_name,
                    "alerts_total_count": data.get("counts", {}).get("total", 0),
                },
            )

            return data
        except requests.exceptions.RequestException as err:
            raise RecordedFutureApiError(
                f"Error while fetching RecordedFuture's API: {err}"
            ) from err

    def _get_paginated_alerts(
        self,
        rule: PrioritiedRule,
        since: datetime,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """
        Paginate and get all alerts for a given rule and time range.
        :param rule: The rule to get alerts for.
        :param since: The date from which to get alerts.
        :param until: The date until which to get alerts (optional).
        :param limit: The maximum number of alerts to retrieve per request (default is 100).
        :param offset: The offset for pagination (default is 0).
        :return: A list of Alert objects.
        """
        alerts = []

        data = self._raw_get_alerts(
            rule=rule,
            triggered_since=since,
            triggered_until=until,
            limit=limit,
            offset=offset,
        )
        for alert in data.get("data", []):
            alerts.append(
                Alert(
                    alert_id=alert["id"],
                    alert_url=alert["url"]["portal"],
                    alert_date=alert["log"]["triggered"],
                    alert_title=alert["title"],
                    alert_ai_insight=alert["ai_insights"]["comment"],
                    alert_rf_rule=rule,
                    alert_hits=alert["hits"],
                )
            )

        offset += len(alerts)
        alerts_count = data.get("counts", {}).get("total", 0)
        if offset < alerts_count:
            alerts.extend(
                self._get_paginated_alerts(
                    rule=rule,
                    since=since,
                    until=until,
                    limit=limit,
                    offset=offset,
                )
            )

        return alerts

    def get_playbook_id(self, category, trigger_from, trigger_to, priority_threshold):
        try:
            from_api = 0
            alert_count = 1
            priority_matrix = {
                "High": ["High"],
                "Moderate": ["High", "Moderate"],
                "Informational": ["High", "Moderate", "Informational"],
            }
            for created_or_updated in ["created", "updated"]:
                while int(from_api) < int(alert_count):
                    response = requests.post(
                        str(self.base_url + "playbook-alert/search"),
                        headers={
                            "X-RFToken": self.x_rf_token,
                            "Content-Type": "application/json",
                            "accept": "application/json",
                        },
                        json={
                            "from": from_api,
                            "limit": 100,
                            "order_by": created_or_updated,
                            "direction": "asc",
                            "category": [str(category)],
                            str(created_or_updated + "_range"): {
                                "from": trigger_from,
                                "until": trigger_to,
                            },
                            "priority": priority_matrix[priority_threshold],
                        },
                    )

                    # If there is an error during the request, the method raise the error
                    response.raise_for_status()

                    # Check if the response has correct content type
                    self._header_response_control(response)

                    data = response.json()

                    # Validates the integrity and expected structure of the response data
                    self._data_control(
                        data=data,
                        expected_status_message="Playbook alert search successful",
                    )

                    # If the response contains data and contains the counts field, extract priority rules
                    if data.get("counts"):

                        if data["counts"]["total"] == 0:
                            alert_count = 0
                            from_api = 1
                        else:
                            alert_count = data["counts"]["total"]
                        from_api = from_api + data["counts"]["returned"]
                        for playbook_alert_summary in data["data"]:
                            self.playbook_alerts_summaries.append(
                                PlaybookAlertSummary(
                                    playbook_alert_id=playbook_alert_summary[
                                        "playbook_alert_id"
                                    ],
                                    priority=playbook_alert_summary["priority"],
                                    created=playbook_alert_summary[created_or_updated],
                                    category=playbook_alert_summary["category"],
                                    title=playbook_alert_summary["title"],
                                )
                            )
                    else:
                        # If data does not contain mandatory counts field, log the error
                        self.helper.connector_logger.error(
                            "Response does not contain mandatory <counts> field"
                        )

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "Exception occured when trying to reach RecordedFuture's API : ",
                {"error": str(e)},
            )
        except Exception as err:
            self.helper.connector_logger.error(err)

    def get_complete_playbook_alert(self, playbook_alert_summary):
        try:
            # If playbook_alert_summary is None, log the error
            if playbook_alert_summary.playbook_alert_id is None:
                self.helper.connector_logger.error(
                    "You must provide an playbook alert summary"
                )

            # If playbook_alert.category is not one of: domain_abuse, identity_novel_exposures, code_repo_leakage, log the error
            playbook_alert_categories = [
                "domain_abuse",
                "identity_novel_exposures",
                "code_repo_leakage",
            ]
            if playbook_alert_summary.category not in playbook_alert_categories:
                self.helper.connector_logger.error(
                    "You must provide an playbook alert whose category is among : domain_abuse, identity_novel_exposures, code_repo_leakage"
                )

            response = requests.post(
                str(
                    self.base_url
                    + "playbook-alert/"
                    + playbook_alert_summary.category
                    + "/"
                    + playbook_alert_summary.playbook_alert_id
                ),
                headers={
                    "X-RFToken": self.x_rf_token,
                    "Content-Type": "application/json",
                    "accept": "application/json",
                },
                json={"panels": ["status", "action", "summary", "dns", "whois", "log"]},
            )

            # If there is an error during the request, the method raise the error
            response.raise_for_status()

            # Check if the response has correct content type
            self._header_response_control(response)

            data = response.json()

            # Validates the integrity and expected structure of the response data
            self._data_control(
                data=data,
                expected_status_message="Playbook alert single lookup successful.",
            )

            return data

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "Exception occured when trying to reach RecordedFuture's API : ",
                {"error": str(e)},
            )
        except Exception as err:
            self.helper.connector_logger.error(err)

    def get_image_alert(self, image_id):
        try:
            response = requests.get(
                str(self.base_url + "v3/alerts/image"),
                headers={
                    "X-RFToken": self.x_rf_token,
                },
                params={
                    "id": str(image_id),
                },
                stream=True,
            )
            if response.status_code == 200:
                image_name = str(image_id + ".png")
                response.raw.decode_content = True
                return True, response.content, image_name
            else:
                self.helper.connector_logger.info(
                    "Perhaps, the image doesn't exist anymore..."
                )
                return False, str("error.png"), str("error.png")
        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.info(
                "Exception occured when trying to reach RecordedFuture's API : "
                + str(e)
            )
            self.helper.connector_logger.info(
                "Perhaps, the image doesn't exist anymore..."
            )
            return False, str("error.png"), str("error.png")
        except:
            return False, str("error.png"), str("error.png")

    def get_alerts(self, rule: PrioritiedRule, since: datetime) -> list[Alert]:
        """
        Get alerts by rule and by trigger date.
        :param rule: The rule to get alerts for.
        :param triggered_since: The date from which to get alerts.
        :return: A list of Alert objects.

        See https://docs.recordedfuture.com/reference/alert-search
        """
        alerts = []

        # Get the first alert to check the total alerts count
        data = self._raw_get_alerts(rule=rule, triggered_since=since, limit=1)
        alerts_count = data.get("counts", {}).get("total", 0)

        # If more than 1000 alerts are found,
        # recover alerts day by day to avoid API pagination limits
        if alerts_count > 1000:
            days_to_recover = (datetime.now(tz=timezone.utc) - since).days
            for day_delta in range(0, days_to_recover + 1):  # exclusive range
                alerts.extend(
                    self._get_paginated_alerts(
                        rule=rule,
                        since=since + timedelta(days=day_delta),
                        until=since + timedelta(days=day_delta + 1),
                    )
                )
        else:
            alerts = self._get_paginated_alerts(rule=rule, since=since)

        return alerts

    def compare_rf_rules_and_vocabularies(self, found_vocabulary):
        self.unfound_rf_rules_in_vocabularies = []
        for rule in self.priorited_rules:
            if not any(
                str(rule.rule_intelligence_goal) == vocab.vocabulary_name
                for vocab in found_vocabulary
            ):
                self.unfound_rf_rules_in_vocabularies.append(rule)
        for rule in self.unfound_rf_rules_in_vocabularies:
            self.helper.connector_logger.info(
                "Unfound Intelligence goal in Vocabularies : "
                + rule.rule_intelligence_goal
            )

    def extract_priority_rules(self, each_rule):
        if len(each_rule["intelligence_goals"]) == 0:
            self.priorited_rules.append(
                PrioritiedRule(each_rule["id"], each_rule["title"], "N/A")
            )
        else:
            self.priorited_rules.append(
                PrioritiedRule(
                    each_rule["id"],
                    each_rule["title"],
                    str(each_rule["intelligence_goals"][0]["name"]),
                )
            )

    def get_prioritedrule_ids(self, limit=100):
        self.priorited_rules = []
        try:
            from_api = 0
            self.alert_count = 1
            while from_api < self.alert_count:
                response = requests.get(
                    str(self.base_url + "v2/alert/rule"),
                    headers={
                        "X-RFToken": self.x_rf_token,
                    },
                    params={"from": str(from_api), "limit": str(limit)},
                )

                # If there is an error during the request, the method raise the error
                response.raise_for_status()

                # Check if the response has correct content type
                self._header_response_control(response)

                data = response.json()

                # Validates the integrity and expected structure of the response data
                self._data_control(data=data)

                # If the response contains data and contains the counts field, extract priority rules
                if data.get("counts"):
                    self.alert_count = data["counts"]["total"]
                    from_api = from_api + data["counts"]["returned"]
                    for each_rule in data["data"]["results"]:
                        if self.priority_alerts_only and each_rule["priority"]:
                            self.extract_priority_rules(each_rule)
                        elif not self.priority_alerts_only:
                            self.extract_priority_rules(each_rule)
                    self.priorited_rules.append(
                        PrioritiedRule(
                            "Fake-Id-Playbook-Alert",
                            "Domain Abuse",
                            "TYPOSQUATTING DETECTION",
                        )
                    )
                else:
                    # If data does not contain mandatory counts field, log the error
                    self.helper.connector_logger.error(
                        "Response does not contain mandatory <counts> field"
                    )
        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "Exception occured when trying to reach RecordedFuture's API : ",
                {"error": str(e)},
            )
        except Exception as err:
            self.helper.connector_logger.error(err)
