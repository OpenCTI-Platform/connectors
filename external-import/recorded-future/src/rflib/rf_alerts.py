import base64
import datetime
import threading
from re import search

import pycti
import pytz
import stix2
from pycti import (
    CustomObjectChannel,
    CustomObservableText,
    Incident,
    StixCoreRelationship,
)

from .constants import TLP_MAP
from .make_markdown_table import make_markdown_table


class Vocabulary:
    def __init__(self, vocabulary_id, vocabulary_name):
        self.vocabulary_id = vocabulary_id
        self.vocabulary_name = vocabulary_name


class RecordedFutureAlertConnector(threading.Thread):
    def __init__(self, helper, rf_alerts_api, opencti_default_severity, tlp):
        threading.Thread.__init__(self)
        self.helper = helper

        self.helper.log_info(
            "Starting Recorded Future Alert connector module initialization"
        )

        self.work_id = None
        self.opencti_default_severity = opencti_default_severity
        self.tlp = TLP_MAP.get(tlp, None)
        self.author = self._create_author()

        self.api_recorded_future = rf_alerts_api

        self.stix_channels = self.helper.api.vocabulary.list(
            **{
                "filters": {
                    "mode": "and",
                    "filterGroups": [],
                    "filters": [
                        {
                            "key": "category",
                            "values": "channel_types_ov",
                        }
                    ],
                }
            }
        )

    def _generate_stix_relationship(
        self,
        source_ref: str,
        stix_core_relationship_type: str,
        target_ref: str,
        start_time: str | None = None,
        stop_time: str | None = None,
    ) -> StixCoreRelationship:
        """
        This method allows you to create a relationship in Stix2 format.

        :param source_ref: This parameter is the "from" of the relationship.
        :param stix_core_relationship_type: This parameter defines the type of relationship between the two entities.
        :param target_ref: This parameter is the "to" of the relationship.
        :param start_time: This parameter is the start of the relationship. Value not required, None by default.
        :param stop_time: This parameter is the stop of the relationship. Value not required, None by default.
        :return: StixCoreRelationship
        """

        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            start_time=start_time,
            stop_time=stop_time,
            target_ref=target_ref,
            created_by_ref=self.author,
            object_marking_refs=self.tlp,
        )

    @staticmethod
    def _create_author():
        """Creates Recorded Future Author"""
        return stix2.Identity(
            id=pycti.Identity.generate_id("Recorded Future", "organization"),
            name="Recorded Future",
            identity_class="organization",
        )

    def update_rules(self):
        self.vocabulary_list = []
        existing_vocabulary = self.helper.api.vocabulary.list(
            **{
                "filters": {
                    "mode": "and",
                    "filterGroups": [],
                    "filters": [
                        {
                            "key": "category",
                            "values": "incident_type_ov",
                        }
                    ],
                }
            }
        )
        for vocab in existing_vocabulary:
            self.vocabulary_list.append(
                Vocabulary(vocabulary_id=vocab["id"], vocabulary_name=vocab["name"])
            )
        self.api_recorded_future.get_prioritedrule_ids(limit=100)
        self.api_recorded_future.compare_rf_rules_and_vocabularies(self.vocabulary_list)
        for newrule in self.api_recorded_future.unfound_rf_rules_in_vocabularies:
            self.helper.api.vocabulary.create(
                **{
                    "name": str(newrule.rule_intelligence_goal),
                    "description": "Vocabulary created by RecordedFuture Alert.",
                    "category": "incident_type_ov",
                }
            )

    def run(self):
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            "Recorded Future Alerts",
        )

        self.update_rules()
        timestamp = datetime.datetime.now(pytz.timezone("UTC"))
        current_state = self.helper.get_state()
        if current_state is not None and "last_alert_run" in current_state:
            current_state_datetime = datetime.datetime.strptime(
                current_state["last_alert_run"], "%Y-%m-%dT%H:%M:%S"
            )
            if current_state_datetime.date() == datetime.datetime.today().date():
                self.run_for_time_period(
                    trigger=str(datetime.datetime.today().date()),
                    after=current_state["last_alert_run"],
                )
                for alert in self.api_recorded_future.alerts:
                    try:
                        self.alert_to_incident(alert)
                    except Exception as err:
                        self.helper.connector_logger.error(
                            "Incident cannot be created",
                            {"alert_id": alert.alert_id, "error_msg": str(err)},
                        )
                    timestamp_checkpoint = datetime.datetime.now(pytz.timezone("UTC"))
                    self.helper.set_state(
                        {
                            "last_alert_run": timestamp_checkpoint.strftime(
                                "%Y-%m-%dT%H:%M:%S"
                            )
                        }
                    )
            else:
                local_alerts = []
                self.run_for_time_period(
                    trigger=str(current_state_datetime.date()),
                    after=current_state["last_alert_run"],
                )
                local_alerts.extend(self.api_recorded_future.alerts)
                day_delta = (
                    datetime.datetime.today().date() - current_state_datetime.date()
                )
                for i in range(1, day_delta.days + 1):
                    day = current_state_datetime.date() + datetime.timedelta(days=i)
                    self.run_for_time_period(trigger=str(day))
                    local_alerts.extend(self.api_recorded_future.alerts)
                for alert in local_alerts:
                    try:
                        self.alert_to_incident(alert)
                    except Exception as err:
                        self.helper.connector_logger.error(
                            "Incident cannot be created",
                            {"alert_id": alert.alert_id, "error_msg": str(err)},
                        )
                    timestamp_checkpoint = datetime.datetime.now(pytz.timezone("UTC"))
                    self.helper.set_state(
                        {
                            "last_alert_run": timestamp_checkpoint.strftime(
                                "%Y-%m-%dT%H:%M:%S"
                            )
                        }
                    )
        else:
            self.run_for_time_period(trigger=str(datetime.datetime.today().date()))
            for alert in self.api_recorded_future.alerts:
                try:
                    self.alert_to_incident(alert)
                except Exception as err:
                    self.helper.connector_logger.error(
                        "Incident cannot be created",
                        {"alert_id": alert.alert_id, "error_msg": str(err)},
                    )
                timestamp_checkpoint = datetime.datetime.now(pytz.timezone("UTC"))
                self.helper.set_state(
                    {
                        "last_alert_run": timestamp_checkpoint.strftime(
                            "%Y-%m-%dT%H:%M:%S"
                        )
                    }
                )

        self.helper.set_state(
            {"last_alert_run": timestamp.strftime("%Y-%m-%dT%H:%M:%S")}
        )
        message = f"{self.helper.connect_name} connector successfully run for Recorded Future Alerts"
        self.helper.api.work.to_processed(self.work_id, message)

    def alert_to_incident(self, alert):
        external_files = []
        bundle_objects = [self.author]
        stix_external_refs = []
        stix_external_ref = stix2.ExternalReference(
            source_name="Recorded Future", url=alert.alert_url
        )
        stix_external_refs.append(stix_external_ref)
        stix_incident = stix2.Incident(
            id=Incident.generate_id(
                str("[" + alert.alert_id + "] " + alert.alert_title), alert.alert_date
            ),
            name=str("[" + alert.alert_id + "] " + alert.alert_title),
            object_marking_refs=self.tlp,
            description="",
            created=alert.alert_date,
            created_by_ref=self.author,
            external_references=[stix_external_ref],
            labels=[alert.alert_rf_rule.rule_name],
            allow_custom=True,
            severity=str(self.opencti_default_severity),
            incident_type=str(alert.alert_rf_rule.rule_intelligence_goal),
            x_opencti_files=external_files,
        )

        reference_number = 0
        for hit in alert.alert_hits:
            reference_number = reference_number + 1
            hit_note = ""
            hit_note = hit_note + "### Fragment \n" + hit["fragment"] + " \n "
            if hit["primary_entity"] is not None:
                hit_note = hit_note + " ### Primary entity : \n"
                table_markdown = ["Key", "value"]
                for key in hit["primary_entity"]:
                    table_markdown.append([key, str(hit["primary_entity"][key])])
                hit_note = hit_note + make_markdown_table(table_markdown)
            hit_note = (
                hit_note + "### Document\n> Title : " + str(hit["document"]["title"])
            )
            hit_note = hit_note + " \n> URL : " + str(hit["document"]["url"]) + " \n "
            hit_note = hit_note + make_markdown_table(
                [
                    ["Document's", "source"],
                    ["id", str(hit["document"]["source"]["id"])],
                    ["name", str(hit["document"]["source"]["name"])],
                    ["type", str(hit["document"]["source"]["type"])],
                ]
            )
            hit_note = hit_note + "\n### Entities"

            for entity in hit["entities"]:
                table_markdown = [["Entity's", "value"]]
                for key in entity:
                    table_markdown.append([key, str(entity[key])])
                hit_note = hit_note + make_markdown_table(table_markdown)
                if entity["type"] == "Image":
                    image_presence, image_data, image_name = (
                        self.api_recorded_future.get_image_alert(entity["name"])
                    )
                    if image_presence:
                        external_files.append(
                            {
                                "name": image_name,
                                "data": base64.b64encode(image_data),
                                "mime_type": "image/png",
                                "objectMarking": self.tlp,
                            }
                        )
                elif entity["type"] == "URL":
                    stix_url = stix2.URL(
                        value=entity["name"],
                        object_marking_refs=self.tlp,
                        custom_properties={
                            "x_opencti_created_by_ref": self.author["id"],
                        },
                    )
                    stix_relationship = self._generate_stix_relationship(
                        stix_incident.id, "related-to", stix_url.id
                    )
                    bundle_objects.append(stix_url)
                    bundle_objects.append(stix_relationship)

                elif entity["type"] == "IpAddress":
                    stix_ipv4address = stix2.IPv4Address(
                        value=entity["name"],
                        object_marking_refs=self.tlp,
                        custom_properties={
                            "x_opencti_created_by_ref": self.author["id"],
                        },
                    )
                    stix_relationship = self._generate_stix_relationship(
                        stix_incident.id, "related-to", stix_ipv4address.id
                    )
                    bundle_objects.append(stix_ipv4address)
                    bundle_objects.append(stix_relationship)
                elif entity["type"] == "EmailAddress":
                    stix_emailaddress = stix2.EmailAddress(
                        value=entity["name"],
                        object_marking_refs=self.tlp,
                        custom_properties={
                            "x_opencti_created_by_ref": self.author["id"],
                        },
                    )
                    stix_relationship = self._generate_stix_relationship(
                        stix_incident.id, "related-to", stix_emailaddress.id
                    )
                    bundle_objects.append(stix_emailaddress)
                    bundle_objects.append(stix_relationship)
                elif entity["type"] == "InternetDomainName":
                    stix_domain = stix2.DomainName(
                        value=entity["name"],
                        object_marking_refs=self.tlp,
                        custom_properties={
                            "x_opencti_created_by_ref": self.author["id"],
                        },
                    )
                    stix_relationship = self._generate_stix_relationship(
                        stix_incident.id, "related-to", stix_domain.id
                    )
                    bundle_objects.append(stix_domain)
                    bundle_objects.append(stix_relationship)
                    stix_external_ref = stix2.ExternalReference(
                        source_name="Recorded Future",
                        url=entity["type"],
                    )
                    stix_external_refs.append(stix_external_ref)
                elif entity["type"] == "Malware":
                    octi_malware = self.helper.api.malware.list(
                        **{
                            "filters": {
                                "mode": "and",
                                "filterGroups": [],
                                "filters": [
                                    {"key": "name", "values": str(entity["name"])}
                                ],
                            }
                        }
                    )
                    if len(octi_malware) > 0:
                        octi_malware = octi_malware[0]
                        stix_relationship = self._generate_stix_relationship(
                            stix_incident.id, "related-to", octi_malware["standard_id"]
                        )
                        bundle_objects.append(stix_relationship)
                elif entity["type"] == "MitreAttackIdentifier":
                    octi_technique_mitre = self.helper.api.attack_pattern.list(
                        **{
                            "filters": {
                                "mode": "and",
                                "filterGroups": [],
                                "filters": [
                                    {"key": "x_mitre_id", "values": str(entity["name"])}
                                ],
                            }
                        }
                    )
                    if len(octi_technique_mitre) > 0:
                        octi_technique_mitre = octi_technique_mitre[0]
                        stix_relationship = self._generate_stix_relationship(
                            stix_incident.id,
                            "related-to",
                            octi_technique_mitre["standard_id"],
                        )
                        bundle_objects.append(stix_relationship)

            if len(hit["document"]["authors"]) > 0:
                hit_note = hit_note + "\n### Authors"
            stix_url_doc = None
            stix_channel = None
            stix_text = None
            if hit["document"]["url"] is not None:
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
                            stix_channel = CustomObjectChannel(
                                id=pycti.Channel.generate_id(channel["name"]),
                                name=str(value).replace("https://", ""),
                                channel_types=channel["name"],
                                description=description,
                                created=alert.alert_date,
                                object_marking_refs=self.tlp,
                                custom_properties={
                                    "x_opencti_created_by_ref": self.author["id"],
                                },
                            )
                            stix_relationship = self._generate_stix_relationship(
                                stix_incident.id, "related-to", stix_channel.id
                            )
                            bundle_objects.append(stix_channel)
                            bundle_objects.append(stix_relationship)
                stix_text = CustomObservableText(
                    value=str(hit["fragment"]),
                    object_marking_refs=self.tlp,
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                    },
                )
                stix_relationship = self._generate_stix_relationship(
                    stix_incident.id, "related-to", stix_text.id
                )
                bundle_objects.append(stix_text)
                bundle_objects.append(stix_relationship)
                stix_url_doc = stix2.URL(
                    value=hit["document"]["url"],
                    object_marking_refs=self.tlp,
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                    },
                )
                stix_relationship = self._generate_stix_relationship(
                    stix_incident.id, "related-to", stix_url_doc.id
                )
                bundle_objects.append(stix_url_doc)
                bundle_objects.append(stix_relationship)
                stix_relationship = self._generate_stix_relationship(
                    stix_url_doc.id, "related-to", stix_text.id
                )
                bundle_objects.append(stix_relationship)
                if stix_channel is not None:
                    stix_relationship = self._generate_stix_relationship(
                        stix_channel.id, "publishes", stix_url_doc.id
                    )
                    bundle_objects.append(stix_relationship)
            for author in hit["document"]["authors"]:
                table_markdown = [["Author's", "value"]]
                for key in author:
                    table_markdown.append([key, str(author[key])])
                hit_note = hit_note + make_markdown_table(table_markdown)
                stix_user = stix2.UserAccount(
                    user_id=author["name"],
                    account_login=author["name"],
                    type="user-account",
                    object_marking_refs=self.tlp,
                    display_name=author["name"],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                    },
                )
                stix_relationship = self._generate_stix_relationship(
                    stix_incident.id, "related-to", stix_user.id
                )
                bundle_objects.append(stix_user)
                bundle_objects.append(stix_relationship)
                if stix_text is not None:
                    stix_relationship = self._generate_stix_relationship(
                        stix_user.id, "related-to", stix_text.id
                    )
                    bundle_objects.append(stix_relationship)
                if stix_url_doc is not None:
                    stix_relationship = self._generate_stix_relationship(
                        stix_url_doc.id, "related-to", stix_user.id
                    )
                    bundle_objects.append(stix_relationship)
                if stix_channel is not None:
                    stix_relationship = self._generate_stix_relationship(
                        stix_channel.id, "related-to", stix_user.id
                    )
                    bundle_objects.append(stix_relationship)
            stix_note = stix2.Note(
                id=pycti.Note.generate_id(
                    hit_note,
                    datetime.datetime.now(pytz.timezone("UTC")).strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                ),
                object_marking_refs=self.tlp,
                abstract=str(
                    " ["
                    + str(hit["id"])
                    + "]### Reference  "
                    + str(reference_number)
                    + " / "
                    + str(len(alert.alert_hits))
                ),
                content=hit_note,
                object_refs=[stix_incident.id],
                created_by_ref=self.author,
            )
            bundle_objects.append(stix_note)

        if len(external_files) > 0:
            stix_incident = stix_incident.new_version(x_opencti_files=external_files)
        bundle_objects.append(stix_incident)

        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        self.helper.send_stix2_bundle(
            bundle,
            update=True,
            work_id=self.work_id,
        )

    def run_for_time_period(self, trigger, after=None):
        assert isinstance(
            trigger, str
        ), "Date must be a string with any format between : yyyy to yyyy-MM-dd'T'HH:mm:ss'Z'"
        self.recordedfuture_alert_time = trigger

        self.api_recorded_future.alerts = []
        self.api_recorded_future.get_alert_by_rule_and_by_trigger(
            self.recordedfuture_alert_time, after=after
        )
        if len(self.api_recorded_future.alerts) == 0:
            self.helper.log_info("[" + str(trigger) + "] No alert found : exiting")
        else:
            self.helper.log_info(
                "["
                + str(trigger)
                + "] "
                + str(len(self.api_recorded_future.alerts))
                + " alerts were found"
            )
        return
