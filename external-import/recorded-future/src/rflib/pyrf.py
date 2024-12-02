import datetime

import requests


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
        x_rf_token,
        helper,
        base_url="https://api.recordedfuture.com/",
        priority_alerts_only: bool = None,
    ):
        self.x_rf_token = x_rf_token
        self.base_url = base_url
        self.priorited_rules = []
        self.unfound_rf_rules_in_vocabularies = []
        self.alerts = []
        self.playbook_alerts = []
        self.helper = helper
        self.playbook_alerts_summaries = []
        self.priority_alerts_only = priority_alerts_only

    def get_playbook_id(self, category, trigger_from, trigger_to, priority_threshold):
        assert self.x_rf_token is not None, "You must provide an XRF-Token."
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
                assert (
                    response.status_code == 200
                ), "Unexpected status code from ApiRecordedFuture: " + str(
                    response.status_code
                )
                assert response.headers.get("Content-Type") == "application/json", (
                    "Unexpected Content-Type from ApiRecordedFuture: "
                    + response.headers.get("Content-Type")
                )
                data = response.json()
                assert isinstance(data, dict), "Response data is not a dictionary"
                assert "data" in data, "Response does not contain mandatory data field"
                assert (
                    "counts" in data
                ), "Response does not contain mandatory counts field"
                assert (
                    "status" in data
                ), "Response does not contain mandatory status field"
                assert (
                    data["status"]["status_code"] == "Ok"
                ), "Response status_code is not Ok"
                assert (
                    data["status"]["status_message"]
                    == "Playbook alert search successful"
                ), "Response status_message is not Ok" + str(
                    data["status"]["status_message"]
                )
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

    def get_complete_playbook_alert(self, playbook_alert_summary):
        assert self.x_rf_token is not None, "You must provide an XRF-Token."
        assert (
            playbook_alert_summary.playbook_alert_id is not None
        ), "You must provide an playbook alert summary"
        assert playbook_alert_summary.category in [
            "domain_abuse",
            "identity_novel_exposures",
            "code_repo_leakage",
        ], "You must provide an playbook alert whose category is among : domain_abuse, identity_novel_exposures, code_repo_leakage"
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
        assert (
            response.status_code == 200
        ), "Unexpected status code from ApiRecordedFuture: " + str(response.status_code)
        assert (
            response.headers.get("Content-Type") == "application/json"
        ), "Unexpected Content-Type from ApiRecordedFuture: " + response.headers.get(
            "Content-Type"
        )
        data = response.json()
        assert isinstance(data, dict), "Response data is not a dictionary"
        assert "data" in data, "Response does not contain mandatory data field"
        assert "status" in data, "Response does not contain mandatory status field"
        assert data["status"]["status_code"] == "Ok", "Response status_code is not Ok"
        assert (
            data["status"]["status_message"]
            == "Playbook alert single lookup successful."
        ), "Response status_message is not Ok : " + str(
            data["status"]["status_message"]
        )
        return data

    def get_data_from_playbook_id(self, playbook_alert):
        assert self.x_rf_token is not None, "You must provide an XRF-Token."
        assert (
            playbook_alert.playbook_alert_id is not None
        ), "You must provide an XRF-Token"

        response = requests.post(
            str(
                self.base_url
                + "playbook-alert/"
                + playbook_alert.playbook_alert_category
                + "/"
                + (playbook_alert.playbook_alert_id).replace(":", "%3A")
            ),
            headers={"X-RFToken": self.x_rf_token, "Content-Type": "application/json"},
            json={"panels": ["summary", "dns", "whois", "log"]},
        )
        data = response.json()
        assert (
            response.status_code == 200
        ), "Unexpected status code from ApiRecordedFuture: " + str(response.status_code)
        assert (
            response.headers.get("Content-Type") == "application/json"
        ), "Unexpected Content-Type from ApiRecordedFuture: " + response.headers.get(
            "Content-Type"
        )
        assert data["status"]["status_code"] == "Ok", (
            "Unexpected response status from ApiRecordedFuture : "
            + data["status"]["status_code"]
        )
        assert (
            data["status"]["status_message"]
            == "Playbook alert single lookup successful."
        ), (
            "Unexpected response message from ApiRecordedFuture : "
            + data["status"]["status_message"]
        )
        return (
            data["data"]["panel_evidence_summary"],
            data["data"]["panel_evidence_dns"],
            data["data"]["panel_evidence_whois"],
            data["data"]["panel_log"],
        )

    def get_playbook_id_from_time_range(self, category, from_date, until_date):
        assert self.x_rf_token is not None, "You must provide an XRF-Token."
        from_api = 0
        self.alert_count = 1
        while int(from_api) < int(self.alert_count):
            response = requests.post(
                str(self.base_url + "playbook-alert/search"),
                headers={
                    "X-RFToken": self.x_rf_token,
                    "Content-Type": "application/json",
                },
                json={
                    "from": 0,
                    "limit": 100,
                    "order_by": "created",
                    "direction": "asc",
                    "category": [category],
                    "created_range": {"from": from_date, "until": until_date},
                },
            )
            data = response.json()
            assert (
                response.status_code == 200
            ), "Unexpected status code from ApiRecordedFuture: " + str(
                response.status_code
            )
            assert response.headers.get("Content-Type") == "application/json", (
                "Unexpected Content-Type from ApiRecordedFuture: "
                + response.headers.get("Content-Type")
            )
            assert data["status"]["status_code"] == "Ok", (
                "Unexpected response status from ApiRecordedFuture : "
                + data["status"]["status_code"]
            )
            assert (
                data["status"]["status_message"] == "Playbook alert search successful"
            ), (
                "Unexpected response message from ApiRecordedFuture : "
                + data["status"]["status_message"]
            )
            if data["counts"]["total"] == 0:
                self.alert_count = 0
                from_api = 1
            else:
                self.alert_count = data["counts"]["total"]
            from_api = from_api + data["counts"]["returned"]
            for each_playbook_alert in data["data"]:
                self.playbook_alerts.append(
                    PlaybookId(
                        each_playbook_alert["playbook_alert_id"],
                        each_playbook_alert["status"],
                        each_playbook_alert["priority"],
                        each_playbook_alert["created"],
                        each_playbook_alert["category"],
                        each_playbook_alert["title"],
                    )
                )

    def get_single_alert(self, alert_id):
        response = requests.get(
            str(self.base_url + "v3/alerts/") + str(alert_id),
            headers={
                "X-RFToken": self.x_rf_token,
            },
        )
        data = response.json()
        self.helper.log_info(data)
        return Alert(
            data["data"]["id"],
            data["data"]["url"]["portal"],
            data["data"]["log"]["triggered"],
            data["data"]["title"],
            data["data"]["ai_insights"]["comment"],
            PrioritiedRule(
                "TEST MANUEL RULE ID", "TEST MANUEL RULE NAME", "TEST MANUEL INTEL GOAL"
            ),
            data["data"]["hits"],
        )

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
                self.helper.log_info("Perhaps, the image doesn't exist anymore...")
                return False, str("error.png"), str("error.png")
        except requests.exceptions.RequestException as e:
            self.helper.log_info(
                "Exception occured when trying to reach RecordedFuture's API : "
                + str(e)
            )
            self.helper.log_info("Perhaps, the image doesn't exist anymore...")
            return False, str("error.png"), str("error.png")
        except:
            return False, str("error.png"), str("error.png")

    def get_alert_by_rule_and_by_trigger(self, date, after=None):
        alert_filtered = 0
        after_log = ""
        if after is not None:
            after_log = " generated after " + str(after)
        date = str(date).replace(" 00:00:00", "")
        for priorited_rule in self.priorited_rules:
            try:
                from_api = 0
                self.alert_count = 1
                while int(from_api) < int(self.alert_count):
                    response = requests.get(
                        str(self.base_url + "v3/alerts"),
                        headers={
                            "X-RFToken": self.x_rf_token,
                        },
                        params={
                            "alertRule": str(priorited_rule.rule_id),
                            "limit": 100,
                            "triggered": str(date),
                            "from": str(from_api),
                        },
                    )

                    # If there is an error during the request, the method raise the error
                    response.raise_for_status()

                    # If there is an unexpected content type, log the error
                    rf_alert_rule_content_type = response.headers.get("Content-Type")

                    if rf_alert_rule_content_type != "application/json":
                        self.helper.log_error(
                            "Unexpected Content-Type from ApiRecordedFuture: ",
                            {"content-type": rf_alert_rule_content_type},
                        )

                    data = response.json()

                    # If the response doesn't contain data, log the error
                    if not data.get("data"):
                        self.helper.log_error(
                            "No data returned from Recorded Future API",
                            {
                                "rule_id": priorited_rule.rule_id,
                                "rule_name": priorited_rule.rule_name,
                            },
                        )

                    # If the response is not a dictionary, log the error
                    if not isinstance(data, dict):
                        self.helper.log_error("Response data is not a dictionary")

                    # If the response contains data and contains the counts field, extract priority rules
                    if data.get("counts"):
                        if data["counts"]["total"] == 0:
                            self.alert_count = 0
                            from_api = 1
                        else:
                            self.alert_count = data["counts"]["total"]
                        from_api = from_api + data["counts"]["returned"]
                        for alert in data["data"]:
                            if after is not None:
                                triggered = alert["log"]["triggered"]
                                triggered = datetime.datetime.strptime(
                                    triggered, "%Y-%m-%dT%H:%M:%S.%fZ"
                                )
                                after_date = datetime.datetime.strptime(
                                    after, "%Y-%m-%dT%H:%M:%S"
                                )
                                if triggered >= after_date:
                                    self.alerts.append(
                                        Alert(
                                            alert["id"],
                                            alert["url"]["portal"],
                                            alert["log"]["triggered"],
                                            alert["title"],
                                            alert["ai_insights"]["comment"],
                                            priorited_rule,
                                            alert["hits"],
                                        )
                                    )
                                else:
                                    alert_filtered = alert_filtered + 1
                            else:
                                self.alerts.append(
                                    Alert(
                                        alert["id"],
                                        alert["url"]["portal"],
                                        alert["log"]["triggered"],
                                        alert["title"],
                                        alert["ai_insights"]["comment"],
                                        priorited_rule,
                                        alert["hits"],
                                    )
                                )
                    else:
                        # If data does not contain mandatory counts field, log the error
                        self.helper.log_error(
                            "Response does not contain mandatory <counts> field"
                        )
            except requests.exceptions.RequestException as e:
                self.helper.log_error(
                    "Exception occured when trying to reach RecordedFuture's API : ",
                    {"error": str(e)},
                )
            except Exception as err:
                self.helper.log_error(err)

        self.helper.log_info(
            "Queried alerts : "
            + str(date)
            + after_log
            + " and "
            + str(alert_filtered)
            + " / "
            + str(int(alert_filtered + len(self.alerts)))
            + " alerts have been filtered."
        )

    def compare_rf_rules_and_vocabularies(self, found_vocabulary):
        self.unfound_rf_rules_in_vocabularies = []
        for rule in self.priorited_rules:
            if not any(
                str(rule.rule_intelligence_goal) == vocab.vocabulary_name
                for vocab in found_vocabulary
            ):
                self.unfound_rf_rules_in_vocabularies.append(rule)
        for rule in self.unfound_rf_rules_in_vocabularies:
            self.helper.log_info(
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

                # If there is an unexpected content type, log the error
                rf_alert_rule_content_type = response.headers.get("Content-Type")

                if rf_alert_rule_content_type != "application/json":
                    self.helper.log_error(
                        "Unexpected Content-Type from ApiRecordedFuture: ",
                        {"content-type": rf_alert_rule_content_type},
                    )

                data = response.json()

                # If the response doesn't contain data, log the error
                if not data.get("data"):
                    self.helper.log_error("No rules returned from Recorded Future API")

                # If the response is not a dictionary, log the error
                if not isinstance(data, dict):
                    self.helper.log_error("Response data is not a dictionary")

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
                    self.helper.log_error(
                        "Response does not contain mandatory <counts> field"
                    )
        except requests.exceptions.RequestException as e:
            self.helper.log_error(
                "Exception occured when trying to reach RecordedFuture's API : ",
                {"error": str(e)},
            )
        except Exception as err:
            self.helper.log_error(err)
