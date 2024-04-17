import datetime
import threading
from os import path
from re import search
from sys import exit
from time import sleep

import pycti
import pytz
import yaml

from .pyrf import RecordedFutureApiClient


class Vocabulary:
    def __init__(self, vocabulary_id, vocabulary_name):
        self.vocabulary_id = vocabulary_id
        self.vocabulary_name = vocabulary_name


class ImageToShowInNote:
    def __init__(self, image_alert_hit_id, image_path, image_name):
        self.image_alert_hit_id = image_alert_hit_id
        self.image_path = image_path
        self.image_name = image_name


class NoteWithCraftedImage:
    def __init__(self, note_alert_hit_id, note_stix_reference, note_abstract):
        self.note_alert_hit_id = note_alert_hit_id
        self.note_stix_reference = note_stix_reference
        self.note_abstract = note_abstract


class RecordedFutureAlertConnector(threading.Thread):
    def __init__(self, helper):
        threading.Thread.__init__(self)
        self.helper = helper

        config_file_path = path.dirname(path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if path.isfile(config_file_path)
            else {}
        )

        self.helper.log_info(
            "Starting Recorded Future Alert connector module initialization"
        )

        # Additional configuration.
        self.opencti_url = pycti.get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config, required=True
        )
        self.opencti_token = pycti.get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config, required=True
        )

        self.recordedfuture_x_rf_token = pycti.get_config_variable(
            "RECORDED_FUTURE_XRFTOKEN", ["rf", "token"], config, required=True
        )
        self.connector_interval = pycti.get_config_variable(
            "CONNECTOR_INTERVAL", ["connector", "download_path"], config, required=True
        )

        self.opencti_incident_vocabulary_name = pycti.get_config_variable(
            "OPENCTI_INCIDENT_VOCABULARY_NAME",
            ["alert", "incident_vocabulary_name"],
            config,
            required=True,
        )
        self.opencti_channels_vocabulary_name = pycti.get_config_variable(
            "OPENCTI_CHANNELS_VOCABULARY_NAME",
            ["alert", "channels_vocabulary_name"],
            config,
            required=True,
        )
        self.opencti_default_marking = pycti.get_config_variable(
            "OPENCTI_DEFAULT_MARKING",
            ["alert", "default_marking"],
            config,
            required=True,
        )
        self.opencti_connector_author_name = pycti.get_config_variable(
            "OPENCTI_CONNECTOR_AUTHOR_NAME",
            ["alert", "connector_author_name"],
            config,
            required=True,
        )
        self.opencti_incident_static_description = pycti.get_config_variable(
            "OPENCTI_INCIDENT_STATIC_DESCRIPTION",
            ["alert", "incident_static_description"],
            config,
            required=True,
        )
        self.connector_initial_pull_off = pycti.get_config_variable(
            "CONNECTOR_INITIAL_PULL_OFF",
            ["alert", "initial_pull_off"],
            config,
            required=False,
            default=1,
        )
        self.connector_download_path = pycti.get_config_variable(
            "CONNECTOR_DOWNLOAD_PATH", ["alert", "download_path"], config, required=True
        )
        self.recordedfuture_logo_abuse_rule_id = pycti.get_config_variable(
            "RECORDED_FUTURE_LOGO_ABUSE_RULE_ID",
            ["alert", "logo_abuse_rule_id"],
            config,
            required=True,
        )

        self.opencti_api_client = pycti.OpenCTIApiClient(
            url=self.opencti_url, token=self.opencti_token, ssl_verify=True
        )

        # Querying incident_type_ov vocabularies
        self.vocabulary_list = []
        existing_vocabulary = self.opencti_api_client.vocabulary.list(
            **{
                "filters": {
                    "mode": "and",
                    "filterGroups": [],
                    "filters": [
                        {
                            "key": "category",
                            "values": self.opencti_incident_vocabulary_name,
                        }
                    ],
                }
            }
        )
        for vocab in existing_vocabulary:
            self.vocabulary_list.append(
                Vocabulary(vocabulary_id=vocab["id"], vocabulary_name=vocab["name"])
            )

        self.api_recorded_future = RecordedFutureApiClient(
            x_rf_token=self.recordedfuture_x_rf_token,
            connector_download_path=self.connector_download_path,
        )
        self.api_recorded_future.get_prioritedrule_ids(limit=100)
        self.api_recorded_future.compare_rf_rules_and_vocabularies(self.vocabulary_list)

        for newrule in self.api_recorded_future.unfound_rf_rules_in_vocabularies:
            self.opencti_api_client.vocabulary.create(
                **{
                    "name": str(
                        self.api_recorded_future.nomenclature + newrule.rule_name
                    ),
                    "description": "Vocabulary created by a new priorited rule in RecordedFuture.",
                    "category": self.opencti_incident_vocabulary_name,
                }
            )

        self.stix_channels = self.opencti_api_client.vocabulary.list(
            **{
                "filters": {
                    "mode": "and",
                    "filterGroups": [],
                    "filters": [
                        {
                            "key": "category",
                            "values": self.opencti_channels_vocabulary_name,
                        }
                    ],
                }
            }
        )

        self.stix_anonymous_user_account = ["A Guest", "Anonymous"]

        self.stix_object_default_marking = (
            self.opencti_api_client.marking_definition.read(
                **{
                    "filters": {
                        "mode": "and",
                        "filterGroups": [],
                        "filters": [
                            {
                                "key": "definition",
                                "values": self.opencti_default_marking,
                            }
                        ],
                    }
                }
            )
        )
        self.stix_author = self.opencti_api_client.identity.list(
            **{
                "filters": {
                    "mode": "and",
                    "filterGroups": [],
                    "filters": [
                        {"key": "name", "values": self.opencti_connector_author_name}
                    ],
                }
            }
        )
        self.stix_author = self.stix_author[0]
        self.severity_links = {
            "High": "03 - high",
            "Moderate": "02 - medium",
            "Informational": "01 - low",
        }

    def generate_trigger_from(self, last_run):
        last_run = datetime.datetime.strptime(last_run, "%Y-%m-%dT%H:%M:%S")
        now = datetime.datetime.now(pytz.timezone("UTC"))
        delta = datetime.timedelta(minutes=1)
        list = []
        while last_run <= now:
            list.append(last_run.strftime("%Y-%m-%dT%H:%M"))
            last_run += delta
        return list

    def run(self):
        while True:
            timestamp = datetime.datetime.now(pytz.timezone("UTC"))
            self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "Recorded Future Alert run @ "
                + timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
            )
            current_state = self.helper.get_state()
            if current_state is not None and "last_alert_run" in current_state:
                self.helper.log_info(
                    "Autostart from " + str(current_state["last_alert_run"]) + " to now"
                )
                triggers = self.generate_trigger_from(current_state["last_alert_run"])
                for trigger in triggers:
                    self.run_for_time_period(trigger)
                self.helper.set_state(
                    {"last_alert_run": timestamp.strftime("%Y-%m-%dT%H:%M:%S")}
                )
                next_time = timestamp + datetime.timedelta(
                    minutes=self.connector_interval
                )
                waiting_time = (
                    next_time - datetime.datetime.now(pytz.timezone("UTC"))
                ).total_seconds()
                if waiting_time > 0:
                    self.helper.log_info(
                        "Going to sleep for " + str(waiting_time) + " seconds."
                    )
                    sleep(waiting_time)
            else:
                self.helper.log_info(
                    "Connector has never run. Doing initial pull of "
                    + str(self.rf_initial_lookback)
                    + " day(s)"
                )
                self.helper.set_state(
                    {"last_alert_run": timestamp.strftime("%Y-%m-%dT%H:%M:%S")}
                )
                from_date_calcul = (
                    datetime.datetime.now()
                    - datetime.timedelta(days=self.connector_initial_pull_off)
                ).strptime("%Y-%m-%d")
                self.run_from_date_to_date(
                    from_date=from_date_calcul,
                    to_date=(datetime.datetime.now()).strptime("%Y-%m-%d"),
                )

    def run_from_date_to_date(self, from_date, to_date):
        assert isinstance(
            from_date, str
        ), "Date must be a string with the following format : yyyy-MM-dd"
        assert isinstance(
            to_date, str
        ), "Date must be a string with the following format : yyyy-MM-dd"
        assert from_date == datetime.datetime.strptime(from_date, "%Y-%m-%d").strftime(
            "%Y-%m-%d"
        ), "Date format must be : yyyy-MM-dd"
        assert to_date == datetime.datetime.strptime(to_date, "%Y-%m-%d").strftime(
            "%Y-%m-%d"
        ), "Date format must be : yyyy-MM-dd"
        # print(f'Running connector from {from_date} to {to_date}')
        self.helper.log_info(
            "Running connector from " + str(from_date) + " to " + str(to_date)
        )
        from_date = datetime.datetime.strptime(from_date, "%Y-%m-%d")
        to_date = datetime.datetime.strptime(to_date, "%Y-%m-%d")

        delta = datetime.timedelta(days=1)
        while from_date <= to_date:
            self.run_for_time_period(trigger=from_date.strftime("%Y-%m-%d"))
            from_date += delta

    def run_for_time_period(self, trigger):
        assert isinstance(
            trigger, str
        ), "Date must be a string with any format between : yyyy to yyyy-MM-dd'T'HH:mm:ss'Z'"
        self.recordedfuture_alert_time = trigger

        # print(f'Running connector for {trigger}')
        self.helper.log_info("Running connector for " + str(trigger))

        self.api_recorded_future.get_alert_by_rule_and_by_trigger(
            self.recordedfuture_alert_time
        )
        if len(self.api_recorded_future.alerts) == 0:
            # print('No alert, exiting.')
            self.helper.log_info("No alert, exiting.")
            exit()
        else:
            # print('\n\n' + str(len(self.api_recorded_future.alerts)) + ' incidents will be created.')
            self.helper.log_info(
                "\n\n"
                + str(len(self.api_recorded_future.alerts))
                + " incidents will be created."
            )

        alert_count_info = 0
        for alert in self.api_recorded_future.alerts:
            alert_count_info = alert_count_info + 1
            self.helper.log_info(
                "\n\nCreating incident  "
                + str(str(alert_count_info))
                + " /  "
                + str(len(self.api_recorded_future.alerts))
            )
            # print('\n\nCreating incident ' + str(alert_count_info) + ' / ' + str(len(self.api_recorded_future.alerts)))
            fragment_count = 1
            stix_external_ref_to_add = []
            stix_observables = []
            stix_user_accounts = []
            stix_notes = []
            stix_images = []
            stix_obersable_channels = []
            stix_external_references = []
            stix_external_references = (
                self.opencti_api_client.external_reference.create(
                    **{
                        "source_name": "Recorded Future",
                        "url": alert.alert_url,
                        "created": alert.alert_date,
                    }
                )
            )
            for hit in alert.alert_hits:
                observable_type = "Text"
                observable_value = None
                stix_obersable_channel = None
                entities_string = ""
                entity_count = 1
                fragment = search(
                    "(https?:\/\/\S+(\.png|\.jpg|\.gif))", hit["fragment"]
                )
                if fragment is None:
                    fragment = hit["fragment"]
                else:
                    fragment = hit["fragment"].replace(
                        str(fragment[0]), str(" ![](" + fragment[0] + ") ")
                    )
                for entity in hit["entities"]:
                    if entity["type"] == "Image":
                        image_presence, image_path, image_name = (
                            self.api_recorded_future.get_image_and_save_temp_file(
                                entity["name"]
                            )
                        )
                        if image_presence:
                            stix_images.append(
                                ImageToShowInNote(
                                    hit["id"],
                                    image_path,
                                    image_name,
                                )
                            )
                    entities_string += str(
                        "entity "
                        + str(entity_count)
                        + " - "
                        + entity["type"]
                        + " : "
                        + entity["name"]
                        + "  \n  "
                    )
                    if entity["type"] == "URL":
                        observable_type = "url"
                        observable_value = entity["name"]
                    entity_count += 1
                if hit["document"]["url"] is not None:
                    observable_type = "url"
                    observable_value = hit["document"]["url"]
                for channel in self.stix_channels:
                    if hit["document"]["source"]["name"] is not None:
                        if (
                            str(channel["name"]).lower()
                            in str(hit["document"]["source"]["name"]).lower()
                        ):
                            value = search(
                                "(https:\/\/t.me\/.+?(?=\/))|(https:\/\/twitter.com\/.+?(?=\/))",
                                hit["document"]["url"],
                            )
                            if value is None:
                                value = hit["document"]["url"]
                                description = "Script couldn't parse URL. Channel created automatically based on Recorded Future's alert."
                            else:
                                value = value[0]
                                description = "Channel created automatically based on Recorded Future's alert."
                            stix_obersable_channel = self.opencti_api_client.channel.create(
                                **{
                                    "created": alert.alert_date,
                                    "channel_types": channel["name"],
                                    "name": str(value).replace("https://", ""),
                                    "description": description,
                                    "objectMarking": self.stix_object_default_marking[
                                        "id"
                                    ],
                                }
                            )
                            stix_obersable_channels.append(stix_obersable_channel)
                    else:
                        self.helper.log_info(
                            "The bug that I never could reproduce is here : "
                            + str(alert["id"])
                            + str(hit["document"])
                        )
                        # print(f'The bug that I never could reproduce is here : {str(alert['id'])}  {str(hit['document'])}')
                if observable_type == "Text":
                    observable_value = (
                        "Text Observable of " + hit["id"] + ". See list below."
                    )
                if (
                    alert.alert_rf_rule.rule_id
                    == self.recordedfuture_logo_abuse_rule_id
                ):
                    if hit["document"]["url"] is not None:
                        stix_external_ref_to_add.append(str(hit["document"]["url"]))
                    else:
                        parsed_url_from_title = search(
                            "([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])",
                            hit["document"]["title"],
                        )
                        if parsed_url_from_title is not None:
                            parsed_url_from_title = parsed_url_from_title[0]
                            parsed_url_from_parsed_url = search(
                                "^(https?:\/\/)?(www\.)?([^\/]+)", parsed_url_from_title
                            )
                            if parsed_url_from_parsed_url is not None:
                                parsed_url_from_parsed_url = parsed_url_from_parsed_url[
                                    0
                                ]
                                composed_url_from_title = (
                                    "https://urlscan.io/domain/"
                                    + str(parsed_url_from_parsed_url)
                                )
                                stix_external_ref_to_add.append(composed_url_from_title)
                                composed_image_from_url = (
                                    "https://urlscan.io/liveshot/?url=https://"
                                    + str(parsed_url_from_title)
                                )
                                fragment = (
                                    fragment
                                    + " LIVESHOT : ![Liveshot not available]("
                                    + str(composed_image_from_url)
                                    + ") "
                                )
                twitter_account_page = search(
                    "(https:\/\/twitter\.com\/(?<=[^a-zA-Z0-9-_\.]))@([A-Za-z]+[A-Za-z0-9-_]+)",
                    observable_value,
                )
                stix_observable = None
                if observable_type == "url" and twitter_account_page is not None:
                    twitter_account_name = (
                        search("@([A-Za-z0-9_]+)", twitter_account_page[0])
                    )[0]
                    stix_observable = (
                        self.opencti_api_client.stix_cyber_observable.create(
                            **{
                                "observableData": {
                                    "account_type": "twitter",
                                    "type": "user-account",
                                    "account_login": twitter_account_name,
                                    "user_id": twitter_account_name,
                                },
                                "created": alert.alert_date,
                                "source": "Recorded Future",
                                "objectMarking": self.stix_object_default_marking["id"],
                            }
                        )
                    )
                else:
                    stix_observable = (
                        self.opencti_api_client.stix_cyber_observable.create(
                            **{
                                "observableData": {
                                    "type": observable_type,
                                    "value": observable_value,
                                    "x_opencti_description": entities_string,
                                },
                                "created": alert.alert_date,
                                "source": "Recorded Future",
                                "objectMarking": self.stix_object_default_marking["id"],
                            }
                        )
                    )
                stix_observables.append(stix_observable)
                stix_note = self.opencti_api_client.note.create(
                    **{
                        "abstract": str(
                            "["
                            + alert.alert_id
                            + "]"
                            + "["
                            + str(fragment_count)
                            + "] "
                            + alert.alert_title
                        ),
                        "content": fragment,
                        "objectMarking": self.stix_object_default_marking["id"],
                        "createdBy": self.stix_author["id"],
                        "note_types": "external",
                    }
                )
                stix_notes.append(
                    NoteWithCraftedImage(
                        hit["id"],
                        stix_note,
                        str(
                            "["
                            + alert.alert_id
                            + "]"
                            + "["
                            + str(fragment_count)
                            + "] "
                            + alert.alert_title
                        ),
                    )
                )
                if stix_obersable_channel is not None:
                    self.opencti_api_client.stix_core_relationship.create(
                        **{
                            "fromId": stix_obersable_channel["id"],
                            "toId": stix_observable["id"],
                            "confidence": 100,
                            "relationship_type": "related-to",
                            "description": "Relationship created automatically based on Recorded Future's alert.",
                            "objectMarking": self.stix_object_default_marking["id"],
                        }
                    )
                if len(hit["document"]["authors"]) > 0:
                    for author in hit["document"]["authors"]:
                        if author["name"] not in self.stix_anonymous_user_account:
                            user_account_id = "Null"
                            striped_account_login = str(author["name"]).replace(
                                "Create by: ", ""
                            )
                            stix_user_account = self.opencti_api_client.stix_cyber_observable.create(
                                **{
                                    "observableData": {
                                        "account_type": hit["document"]["source"][
                                            "name"
                                        ],
                                        "type": "user-account",
                                        "account_login": striped_account_login,
                                        "user_id": user_account_id,
                                    },
                                    "created": alert.alert_date,
                                    "source": "Recorded Future",
                                    "objectMarking": self.stix_object_default_marking[
                                        "id"
                                    ],
                                }
                            )
                            stix_user_accounts.append(stix_user_account)
                            if stix_obersable_channel is not None:
                                self.opencti_api_client.stix_core_relationship.create(
                                    **{
                                        "fromId": stix_user_account["id"],
                                        "toId": stix_obersable_channel["id"],
                                        "confidence": 100,
                                        "relationship_type": "related-to",
                                        "description": "Relationship created automatically based on Recorded Future's alert.",
                                        "objectMarking": self.stix_object_default_marking[
                                            "id"
                                        ],
                                    }
                                )
                            self.opencti_api_client.stix_core_relationship.create(
                                **{
                                    "fromId": stix_user_account["id"],
                                    "toId": stix_observable["id"],
                                    "confidence": 100,
                                    "relationship_type": "related-to",
                                    "description": "Relationship created automatically based on Recorded Future's alert.",
                                    "objectMarking": self.stix_object_default_marking[
                                        "id"
                                    ],
                                }
                            )
                fragment_count += 1
            stix_external_references_list = [stix_external_references["id"]]
            for stix_external_reference_url in stix_external_ref_to_add:
                stix_external_reference = (
                    self.opencti_api_client.external_reference.create(
                        **{
                            "created": alert.alert_date,
                            "url": stix_external_reference_url,
                            "source_name": "urlscan",
                            "objectMarking": self.stix_object_default_marking["id"],
                        }
                    )
                )
                stix_external_references_list.append(stix_external_reference["id"])
            stix_label = self.opencti_api_client.label.read_or_create_unchecked(
                **{
                    "value": alert.alert_rf_rule.rule_intelligence_goal,
                    "color": "#4a90e2",
                }
            )
            stix_incident = self.opencti_api_client.incident.create(
                **{
                    "name": str("[" + alert.alert_id + "]" + " " + alert.alert_title),
                    "description": str(self.opencti_incident_static_description),
                    "incident_type": str(
                        self.api_recorded_future.nomenclature
                        + alert.alert_rf_rule.rule_name
                    ),
                    "created": alert.alert_date,
                    "externalReferences": stix_external_references_list,
                    "objectMarking": self.stix_object_default_marking["id"],
                    "source": "Recorded Future",
                    "objectLabel": stix_label["id"],
                }
            )
            for stix_image in stix_images:
                self.opencti_api_client.stix_domain_object.add_file(
                    **{"id": stix_incident["id"], "file_name": stix_image.image_path}
                )
            for stix_note in stix_notes:
                self.opencti_api_client.note.add_stix_object_or_stix_relationship(
                    **{
                        "id": stix_note.note_stix_reference["id"],
                        "stixObjectOrStixRelationshipId": stix_incident["id"],
                        "objectMarking": self.stix_object_default_marking["id"],
                    }
                )
                for stix_image in stix_images:
                    if stix_image.image_alert_hit_id == stix_note.note_alert_hit_id:
                        new_fragment = (
                            "![Image Not Found]("
                            + self.opencti_url
                            + "/storage/view/import%2FIncident%2F"
                            + stix_incident["id"]
                            + "%2F"
                            + stix_image.image_name
                            + ")"
                        )
                        new_note = self.opencti_api_client.note.create(
                            **{
                                "abstract": "[IMAGE]" + stix_note.note_abstract,
                                "content": new_fragment,
                                "objectMarking": self.stix_object_default_marking["id"],
                                "createdBy": self.stix_author["id"],
                                "note_types": "external",
                            }
                        )
                        self.opencti_api_client.note.add_stix_object_or_stix_relationship(
                            **{
                                "id": new_note["id"],
                                "stixObjectOrStixRelationshipId": stix_incident["id"],
                                "objectMarking": self.stix_object_default_marking["id"],
                            }
                        )
            for stix_user_account in stix_user_accounts:
                self.opencti_api_client.stix_core_relationship.create(
                    **{
                        "fromId": stix_user_account["id"],
                        "toId": stix_incident["id"],
                        "confidence": 100,
                        "relationship_type": "related-to",
                        "description": "Relationship created automatically based on Recorded Future's alert.",
                        "objectMarking": self.stix_object_default_marking["id"],
                    }
                )
            for stix_observable in stix_observables:
                self.opencti_api_client.stix_core_relationship.create(
                    **{
                        "fromId": stix_observable["id"],
                        "toId": stix_incident["id"],
                        "confidence": 100,
                        "relationship_type": "related-to",
                        "description": "Relationship created automatically based on Recorded Future's alert.",
                        "objectMarking": self.stix_object_default_marking["id"],
                    }
                )
            for stix_obersable_channel in stix_obersable_channels:
                self.opencti_api_client.stix_core_relationship.create(
                    **{
                        "fromId": stix_obersable_channel["id"],
                        "toId": stix_incident["id"],
                        "confidence": 100,
                        "relationship_type": "related-to",
                        "description": "Relationship created automatically based on Recorded Future's alert.",
                        "objectMarking": self.stix_object_default_marking["id"],
                    }
                )


if __name__ == "__main__":
    RfCon = RecordedFutureAlertConnector()
    # RfCon.run_from_date_to_date('2024-03-15','2024-03-16')
    # RfCon.run_for_time_period('2024-03-18T23:00')
    # RfCon.run_playbook_from_time_range('','','')
