import os
import shutil
from re import search
from time import sleep

import requests


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
        connector_download_path,
        helper,
        base_url="https://api.recordedfuture.com/",
        nomenclature="",
    ):
        self.x_rf_token = x_rf_token
        self.base_url = base_url
        self.priorited_rules = []
        self.unfound_rf_rules_in_vocabularies = []
        self.nomenclature = nomenclature
        self.alerts = []
        self.connector_download_path = connector_download_path
        self.deleteImages()
        self.playbook_alerts = []
        self.helper = helper

    def print_all(self):
        for each_playbook_alert in self.playbook_alerts:
            self.helper.log_info(
                each_playbook_alert.playbook_alert_id
                + " - "
                + each_playbook_alert.playbook_alert_title
                + " - "
                + each_playbook_alert.playbook_alert_priority
            )

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
            if from_api == 0:
                self.helper.log_info(
                    "RF Rule : " + str(data["counts"]["total"]) + " category"
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

    def deleteImages(self):
        for filename in os.listdir(self.connector_download_path):
            file_path = os.path.join(self.connector_download_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    if file_path.lower().endswith((".png")):
                        os.unlink(file_path)
                elif os.path.isdir(file_path):
                    # shutil.rmtree(file_path)
                    self.helper.log_info(file_path)
            except Exception as e:
                self.helper.log_info("Failed to delete %s. Reason: %s" % (file_path, e))

    def get_image_and_save_temp_file(self, image_id):
        regexed_image_id = search(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", image_id
        )
        assert (
            regexed_image_id is not None
        ), "You must provide a valide uuid v4 image id"
        try:
            response = requests.get(
                str(self.base_url + "v3/alerts/image"),
                headers={
                    "X-RFToken": self.x_rf_token,
                    "Content-Type": "multipar/form-data",
                },
                params={
                    "id": str(regexed_image_id[0]),
                },
                stream=True,
            )
            assert (
                response.status_code == 200
            ), "Unexpected status code from ApiRecordedFuture: " + str(
                response.status_code
            )
            assert response.headers.get("Content-Type") == "image/png;charset=utf-8", (
                "Unexpected Content-Type from ApiRecordedFuture: "
                + response.headers.get("Content-Type")
            )
            image_name = str(self.connector_download_path + image_id + ".png")
            with open(image_name, "wb") as f:
                response.raw.decode_content = True
                shutil.copyfileobj(response.raw, f)
            return True, image_name, str(image_id + ".png")
        except requests.exceptions.RequestException as e:
            self.helper.log_info(
                "Exception occured when trying to reach RecordedFuture's API : "
                + str(e)
            )
            self.helper.log_info("Perhaps, the image doesn't exist anymore...")
            return False, str("images.png"), str("images.png")
        except:
            raise RuntimeError("Unexpected error")

    def get_alert_by_rule_and_by_trigger(self, trigger):
        assert self.x_rf_token is not None, "You must provide an XRF-Token."
        for priorited_rule in self.priorited_rules:
            try:
                from_api = 0
                self.alert_count = 1
                while int(from_api) < int(self.alert_count):
                    response = requests.get(
                        str(self.base_url + "v3/alerts"),
                        headers={
                            "X-RFToken": self.x_rf_token,
                            "Content-Type": "multipar/form-data",
                        },
                        params={
                            "alertRule": str(priorited_rule.rule_id),
                            "limit": 10,
                            "triggered": str(trigger),
                            "from": str(from_api),
                        },
                    )
                    assert (
                        response.status_code == 200
                    ), "Unexpected status code from ApiRecordedFuture: " + str(
                        response.status_code
                    )
                    assert (
                        response.headers.get("Content-Type")
                        == "application/json;charset=utf-8"
                    ), (
                        "Unexpected Content-Type from ApiRecordedFuture: "
                        + response.headers.get("Content-Type")
                    )
                    data = response.json()
                    assert isinstance(data, dict), "Response data is not a dictionary"
                    assert (
                        "data" in data
                    ), "Response does not contain mandatory data field"
                    assert (
                        "counts" in data
                    ), "Response does not contain mandatory counts field"
                    if from_api == 0:
                        self.helper.log_info(
                            "RF Rule : "
                            + str(data["counts"]["total"])
                            + " - "
                            + priorited_rule.rule_name
                        )
                    if data["counts"]["total"] == 0:
                        self.alert_count = 0
                        from_api = 1
                    else:
                        self.alert_count = data["counts"]["total"]
                    from_api = from_api + data["counts"]["returned"]
                    for alert in data["data"]:
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
            except requests.exceptions.RequestException as e:
                raise RuntimeError(
                    "Exception occured when trying to reach RecordedFuture's API : "
                    + str(e)
                )
            except:
                raise RuntimeError("Unexpected error")

    def compare_rf_rules_and_vocabularies(self, found_vocabulary):
        for rule in self.priorited_rules:
            if not any(
                str(self.nomenclature + rule.rule_name) == vocab.vocabulary_name
                for vocab in found_vocabulary
            ):
                self.unfound_rf_rules_in_vocabularies.append(rule)
        for rule in self.unfound_rf_rules_in_vocabularies:
            self.helper.log_info("Unfound Rule in Vocabularies : " + rule.rule_name)

    def get_prioritedrule_ids(self, limit=100):
        try:
            from_api = 0
            self.alert_count = 1
            while from_api < self.alert_count:
                sleep(1)
                response = requests.get(
                    str(self.base_url + "v2/alert/rule"),
                    headers={
                        "X-RFToken": self.x_rf_token,
                        "Content-Type": "multipar/form-data",
                    },
                    params={"from": str(from_api), "limit": str(limit)},
                )
                assert (
                    response.status_code == 200
                ), "Unexpected status code from ApiRecordedFuture: " + str(
                    response.status_code
                )
                assert (
                    response.headers.get("Content-Type")
                    == "application/json;charset=utf-8"
                ), (
                    "Unexpected Content-Type from ApiRecordedFuture: "
                    + response.headers.get("Content-Type")
                )
                data = response.json()
                assert isinstance(data, dict), "Response data is not a dictionary"
                assert "data" in data, "Response does not contain mandatory data field"
                assert (
                    "counts" in data
                ), "Response does not contain mandatory counts field"
                self.alert_count = data["counts"]["total"]
                from_api = from_api + data["counts"]["returned"]
                for each_rule in data["data"]["results"]:
                    if each_rule["priority"]:
                        if len(each_rule["intelligence_goals"]) == 0:
                            self.priorited_rules.append(
                                PrioritiedRule(
                                    each_rule["id"], each_rule["title"], "N/A"
                                )
                            )
                        else:
                            self.priorited_rules.append(
                                PrioritiedRule(
                                    each_rule["id"],
                                    each_rule["title"],
                                    str(each_rule["intelligence_goals"][0]["name"]),
                                )
                            )
            self.priorited_rules.append(
                PrioritiedRule(
                    "Fake-Id-Playbook-Alert", "Domain Abuse", "TYPOSQUATTING DETECTION"
                )
            )
        except requests.exceptions.RequestException as e:
            raise RuntimeError(
                "Exception occured when trying to reach RecordedFuture's API : "
                + str(e)
            )
        except:
            raise RuntimeError("Unexpected error")
