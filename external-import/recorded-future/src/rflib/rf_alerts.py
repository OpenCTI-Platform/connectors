import base64
import datetime
import threading
from re import search

import pycti
import pytz
import stix2
import tldextract
from pycti import Incident

from .constants import TLP_MAP
from .make_markdown_table import make_markdown_table
from .pyrf import RecordedFutureApiClient


@stix2.CustomObject(
    "fakechannelbecauseofbug",
    [
        ("name", stix2.properties.StringProperty(required=True)),
        ("description", stix2.properties.StringProperty()),
        (
            "channel_types",
            stix2.properties.ListProperty(contained=stix2.properties.StringProperty()),
        ),
        ("object_marking_refs", stix2.properties.STIXObjectProperty()),
        ("createdBy", stix2.properties.StringProperty()),
        ("created", stix2.properties.StringProperty()),
    ],
)
class OpenCTIChannel:
    pass


@stix2.CustomObject(
    "text",
    [
        ("value", stix2.properties.StringProperty(required=True)),
        ("object_marking_refs", stix2.properties.STIXObjectProperty()),
    ],
)
class OpenCTIText:
    pass


class Vocabulary:
    def __init__(self, vocabulary_id, vocabulary_name):
        self.vocabulary_id = vocabulary_id
        self.vocabulary_name = vocabulary_name


class RecordedFutureAlertConnector(threading.Thread):
    def __init__(self, helper, rf_token, opencti_default_severity, tlp):
        threading.Thread.__init__(self)
        self.helper = helper

        self.helper.log_info(
            "Starting Recorded Future Alert connector module initialization"
        )

        self.work_id = None
        self.opencti_default_severity = opencti_default_severity
        self.tlp = TLP_MAP.get(tlp, None)
        self.author = self._create_author()

        self.api_recorded_future = RecordedFutureApiClient(
            x_rf_token=rf_token,
            helper=helper,
            base_url="https://api.recordedfuture.com/",
        )

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

    @staticmethod
    def _create_author():
        """Creates Recorded Future Author"""
        return stix2.Identity(
            id=pycti.Identity.generate_id("Recorded Future", "organization"),
            name="Recorded Future",
            identity_class="organization",
        )

    def get_root_domain(self, url):
        extracted = tldextract.extract(url)
        return extracted.registered_domain

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
                        self.helper.log_error(err)
                        self.create_bugged_incident(alert)
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
                        self.helper.log_error(err)
                        self.create_bugged_incident(alert)
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
                    self.helper.log_error(err)
                    self.create_bugged_incident(alert)
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

    def create_bugged_incident(self, alert):
        bundle_objects = []
        alert_name = str("[BUGGED] " + str(alert.alert_id))
        alert_description = "A bug was encountered while creating incident " + str(
            alert.alert_id
        )
        stix_incident = stix2.Incident(
            id=pycti.Incident.generate_id(
                alert_name,
                datetime.datetime.now(pytz.timezone("UTC")).strftime(
                    "%Y-%m-%dT%H:%M:%S"
                ),
            ),
            name=alert_name,
            description=alert_description,
            object_marking_refs=self.tlp,
            labels=["BUGGED"],
            created_by_ref=self.author,
        )
        bundle_objects.append(stix_incident)
        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        self.helper.log_error(str(bundle))
        self.helper.send_stix2_bundle(bundle, update=True, work_id=self.work_id)

    def alert_to_incident(self, alert):
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
            x_opencti_files=[],
        )
        bundle_objects.append(stix_incident)
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

            image_list = []
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
                        image_list.append(
                            {
                                "name": image_name,
                                "data": base64.b64encode(image_data),
                                "mime_type": "image/png",
                                "objectMarking": self.tlp,
                            }
                        )
                elif entity["type"] == "URL":
                    stix_url = stix2.URL(
                        value=entity["name"], object_marking_refs=self.tlp
                    )
                    stix_relationship = stix2.Relationship(
                        relationship_type="related-to",
                        source_ref=stix_incident.id,
                        target_ref=stix_url.id,
                        created_by_ref=self.author,
                    )
                    bundle_objects.append(stix_url)
                    bundle_objects.append(stix_relationship)
                    value = search(
                        "(https:\/\/t.me\/.+?(?=\/))|(https:\/\/twitter.com\/.+?(?=\/))",
                        str(entity["name"]),
                    )
                    if value is None:
                        root_domain = self.get_root_domain(entity["name"])
                        stix_external_ref = stix2.ExternalReference(
                            source_name="urlscan.io",
                            url="https://urlscan.io/domain/" + str(root_domain),
                        )
                        stix_external_refs.append(stix_external_ref)
                        bundle_objects[0] = bundle_objects[0].new_version(
                            external_references=stix_external_refs
                        )
                elif entity["type"] == "IpAddress":
                    stix_ipv4address = stix2.IPv4Address(
                        value=entity["name"],
                        object_marking_refs=self.tlp,
                        custom_properties={
                            "x_opencti_created_by_ref": self.author,
                        },
                    )
                    stix_relationship = stix2.Relationship(
                        relationship_type="related-to",
                        source_ref=stix_incident.id,
                        target_ref=stix_ipv4address.id,
                        created_by_ref=self.author,
                    )
                    bundle_objects.append(stix_ipv4address)
                    bundle_objects.append(stix_relationship)
                elif entity["type"] == "EmailAddress":
                    stix_emailaddress = stix2.EmailAddress(
                        value=entity["name"],
                        object_marking_refs=self.tlp,
                        custom_properties={
                            "x_opencti_created_by_ref": self.author,
                        },
                    )
                    stix_relationship = stix2.Relationship(
                        relationship_type="related-to",
                        source_ref=stix_incident.id,
                        target_ref=stix_emailaddress.id,
                        created_by_ref=self.author,
                    )
                    bundle_objects.append(stix_emailaddress)
                    bundle_objects.append(stix_relationship)
                elif entity["type"] == "InternetDomainName":
                    stix_domain = (
                        stix2.DomainName(
                            value=entity["name"],
                            object_marking_refs=self.tlp,
                            custom_properties={
                                "x_opencti_created_by_ref": self.author,
                            },
                        ),
                    )
                    stix_relationship = stix2.Relationship(
                        relationship_type="related-to",
                        source_ref=stix_incident.id,
                        target_ref=stix_domain.id,
                        created_by_ref=self.author,
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
                        stix_relationship = stix2.Relationship(
                            relationship_type="related-to",
                            source_ref=stix_incident.id,
                            target_ref=octi_malware["standard_id"],
                            created_by_ref=self.author,
                        )
                        bundle_objects.append(stix_relationship)
                elif entity["type"] == "MitreAttackIdentifier":
                    octi_technique_mittre = self.helper.api.attack_pattern.list(
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
                    if len(octi_technique_mittre) > 0:
                        octi_technique_mittre = octi_technique_mittre[0]
                        stix_relationship = stix2.Relationship(
                            relationship_type="related-to",
                            source_ref=stix_incident.id,
                            target_ref=octi_technique_mittre["standard_id"],
                            created_by_ref=self.author,
                        )
                        bundle_objects.append(stix_relationship)
            if len(image_list) > 0:
                bundle_objects[0] = bundle_objects[0].new_version(
                    x_opencti_files=image_list
                )
            if len(hit["document"]["authors"]) > 0:
                hit_note = hit_note + "\n### Authors"
            stix_url_doc = None
            stix_channel = None
            stix_text = None
            if hit["document"]["url"] is not None:
                description = ""
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
                            stix_channel = OpenCTIChannel(
                                **{
                                    "created": alert.alert_date,
                                    "channel_types": channel["name"],
                                    "name": str(value).replace("https://", ""),
                                    "description": description,
                                    "object_marking_refs": self.tlp,
                                }
                            )
                            stix_relationship = stix2.Relationship(
                                relationship_type="related-to",
                                source_ref=stix_incident.id,
                                target_ref=stix_channel.id,
                                created_by_ref=self.author,
                            )
                            bundle_objects.append(stix_channel)
                            bundle_objects.append(stix_relationship)
                stix_text = OpenCTIText(
                    **{
                        "value": str(hit["fragment"]),
                        "object_marking_refs": self.tlp,
                    }
                )
                stix_relationship = stix2.Relationship(
                    relationship_type="related-to",
                    source_ref=stix_incident.id,
                    target_ref=stix_text.id,
                    created_by_ref=self.author,
                )
                bundle_objects.append(stix_text)
                bundle_objects.append(stix_relationship)
                stix_url_doc = stix2.URL(
                    value=hit["document"]["url"],
                    object_marking_refs=self.tlp,
                )
                stix_relationship = stix2.Relationship(
                    relationship_type="related-to",
                    source_ref=stix_incident.id,
                    target_ref=stix_url_doc.id,
                    created_by_ref=self.author,
                )
                bundle_objects.append(stix_url_doc)
                bundle_objects.append(stix_relationship)
                stix_relationship = stix2.Relationship(
                    relationship_type="related-to",
                    source_ref=stix_url_doc.id,
                    target_ref=stix_text.id,
                    created_by_ref=self.author,
                )
                bundle_objects.append(stix_relationship)
                if stix_channel is not None:
                    stix_relationship = stix2.Relationship(
                        relationship_type="publishes",
                        source_ref=stix_channel.id,
                        target_ref=stix_url_doc.id,
                        created_by_ref=self.author,
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
                        "x_opencti_created_by_ref": self.author,
                    },
                )
                stix_relationship = stix2.Relationship(
                    relationship_type="related-to",
                    source_ref=stix_incident.id,
                    target_ref=stix_user.id,
                    created_by_ref=self.author,
                )
                bundle_objects.append(stix_user)
                bundle_objects.append(stix_relationship)
                stix_relationship = stix2.Relationship(
                    relationship_type="related-to",
                    source_ref=stix_user.id,
                    target_ref=stix_text.id,
                    created_by_ref=self.author,
                )
                bundle_objects.append(stix_relationship)
                if stix_url_doc is not None:
                    stix_relationship = stix2.Relationship(
                        relationship_type="related-to",
                        target_ref=stix_url_doc.id,
                        source_ref=stix_user.id,
                        created_by_ref=self.author,
                    )
                    bundle_objects.append(stix_relationship)
                if stix_channel is not None:
                    stix_relationship = stix2.Relationship(
                        relationship_type="related-to",
                        target_ref=stix_channel.id,
                        source_ref=stix_user.id,
                        created_by_ref=self.author,
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
        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
        self.helper.log_error(str(bundle).replace("fakechannelbecauseofbug", "channel"))
        self.helper.send_stix2_bundle(
            str(bundle).replace("fakechannelbecauseofbug", "channel"),
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
