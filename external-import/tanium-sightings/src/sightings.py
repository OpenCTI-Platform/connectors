#################
# SIGHTINGS     #
#################
import json
import threading
import time
from datetime import datetime

import pytz
import stix2
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from pycti import (
    AttackPattern,
    CustomObservableHostname,
    Incident,
    StixCoreRelationship,
    StixSightingRelationship,
)


class Sightings(threading.Thread):
    def __init__(
        self, helper, tanium_api_handler, tanium_import_alerts, tanium_url_console
    ):
        threading.Thread.__init__(self)
        self.helper = helper
        self.tanium_api_handler = tanium_api_handler
        self.tanium_import_alerts = tanium_import_alerts
        self.tanium_url_console = tanium_url_console

        # Identity
        self.identity = self.helper.api.identity.create(
            type="System",
            name=self.helper.get_name(),
            description=self.helper.get_name(),
        )

    def run(self):
        self.helper.log_info("[SIGHTINGS/INCIDENTS] Starting alerts gatherer")
        while True:
            alerts = self.tanium_api_handler._query(
                "get",
                "/plugin/products/threat-response/api/v1/alerts",
                {"sort": "-createdAt"},
            )
            state = self.helper.get_state()
            if state and "lastAlertDate" in state:
                last_alert_date = parse(state["lastAlertDate"])
            else:
                last_alert_date = datetime.now().astimezone(pytz.UTC) - relativedelta(
                    years=1
                )

            alerts = reversed(alerts)
            for alert in alerts:
                alert_date = parse(alert["createdAt"]).astimezone(pytz.UTC)
                if alert_date > last_alert_date and alert["state"] != "suppressed":
                    # Get intel
                    intel = self.tanium_api_handler._query(
                        "get",
                        "/plugin/products/threat-response/api/v1/intels/"
                        + str(alert["intelDocId"]),
                    )
                    alert_details = json.loads(alert["details"])
                    # Mark as processed
                    if state is not None:
                        state["lastAlertDate"] = alert_date.isoformat()
                        self.helper.set_state(state)
                    else:
                        self.helper.set_state({"lastAlertDate": alert_date.isoformat()})
                    # Create the bundle
                    objects = []
                    # Check if the intel is in OpenCTI
                    external_reference = self.helper.api.external_reference.read(
                        filters={
                            "mode": "and",
                            "filters": [
                                {"key": "source_name", "values": ["Tanium"]},
                                {
                                    "key": "external_id",
                                    "values": [str(alert["intelDocId"])],
                                },
                            ],
                            "filterGroups": [],
                        }
                    )
                    entity = None
                    if external_reference is not None:
                        entity = self.helper.api.stix_domain_object.read(
                            filters={
                                "mode": "and",
                                "filters": [
                                    {
                                        "key": "externalReferences",
                                        "values": [external_reference["id"]],
                                    }
                                ],
                                "filterGroups": [],
                            }
                        )
                        if entity is None:
                            entity = self.helper.api.stix_cyber_observable.read(
                                filters={
                                    "mode": "and",
                                    "filters": [
                                        {
                                            "key": "externalReferences",
                                            "values": [external_reference["id"]],
                                        }
                                    ],
                                    "filterGroups": [],
                                }
                            )
                        if entity is not None:
                            stix_sighting = stix2.Sighting(
                                id=StixSightingRelationship.generate_id(
                                    entity["standard_id"],
                                    self.identity["standard_id"],
                                    alert_date,
                                    alert_date,
                                ),
                                sighting_of_ref=entity["standard_id"],
                                where_sighted_refs=[self.identity["standard_id"]],
                                count=1,
                                confidence=self.helper.connect_confidence_level,
                            )
                            objects.append(stix_sighting)
                    if self.tanium_import_alerts:
                        incident_name = intel["name"] + " on " + alert["computerName"]
                        stix_incident = stix2.Incident(
                            id=Incident.generate_id(incident_name, alert_date),
                            created=alert_date,
                            name=incident_name,
                            description="Type: "
                            + alert["type"]
                            + " | MatchType:"
                            + alert["matchType"],
                            object_marking_refs=[stix2.TLP_RED],
                            created_by_ref=self.identity["standard_id"],
                            confidence=self.helper.connect_confidence_level,
                            external_references=[
                                {
                                    "source_name": "Tanium Threat Response",
                                    "url": self.tanium_url_console
                                    + "/ui/threatresponse/alerts?guid="
                                    + alert["guid"],
                                    "external_id": alert["guid"],
                                }
                            ],
                            allow_custom=True,
                            custom_properties={
                                "source": "Tanium Threat Response",
                                "severity": alert["priority"],
                                "incident_type": "alert",
                            },
                        )
                        objects.append(stix_incident)
                        if entity is not None:
                            if entity["entity_type"] == "Indicator":
                                stix_relation_indicator = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "indicates",
                                        entity["standard_id"],
                                        stix_incident.id,
                                    ),
                                    relationship_type="indicates",
                                    source_ref=entity["standard_id"],
                                    target_ref=stix_incident.id,
                                    object_marking_refs=[stix2.TLP_RED],
                                    created_by_ref=self.identity["standard_id"],
                                )
                                objects.append(stix_relation_indicator)
                            else:
                                stix_relation_observable = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "related-to",
                                        entity["standard_i"],
                                        stix_incident.id,
                                    ),
                                    relationship_type="related-to",
                                    source_ref=entity["standard_id"],
                                    target_ref=stix_incident.id,
                                    object_marking_refs=[stix2.TLP_RED],
                                    created_by_ref=self.identity["standard_id"],
                                )
                                objects.append(stix_relation_observable)

                        stix_hostname = CustomObservableHostname(
                            value=alert["computerName"],
                            object_marking_refs=[stix2.TLP_RED],
                            custom_properties={
                                "created_by_ref": self.identity["standard_id"],
                            },
                        )
                        objects.append(stix_hostname)
                        stix_relation_hostname = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", stix_hostname.id, stix_incident.id
                            ),
                            relationship_type="related-to",
                            source_ref=stix_hostname.id,
                            target_ref=stix_incident.id,
                            object_marking_refs=[stix2.TLP_RED],
                            created_by_ref=self.identity["standard_id"],
                        )
                        objects.append(stix_relation_hostname)
                        stix_ip = stix2.IPv4Address(
                            value=alert["computerIpAddress"],
                            object_marking_refs=[stix2.TLP_RED],
                            custom_properties={
                                "created_by_ref": self.identity["standard_id"],
                            },
                        )
                        objects.append(stix_ip)
                        stix_relation_ip = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", stix_ip.id, stix_incident.id
                            ),
                            relationship_type="related-to",
                            source_ref=stix_ip.id,
                            target_ref=stix_incident.id,
                            object_marking_refs=[stix2.TLP_RED],
                            created_by_ref=self.identity["standard_id"],
                        )
                        objects.append(stix_relation_ip)
                        if (
                            "match" in alert_details
                            and alert_details["match"] is not None
                            and "properties" in alert_details["match"]
                            and "user" in alert_details["match"]["properties"]
                        ):
                            login = alert_details["match"]["properties"]["user"].split(
                                "\\"
                            )[-1]
                            stix_user = stix2.UserAccount(
                                account_login=login,
                                object_marking_refs=[stix2.TLP_RED],
                                custom_properties={
                                    "created_by_ref": self.identity["standard_id"],
                                },
                            )
                            objects.append(stix_user)
                            stix_relation_user = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to", stix_user.id, stix_incident.id
                                ),
                                relationship_type="related-to",
                                source_ref=stix_user.id,
                                target_ref=stix_incident.id,
                                object_marking_refs=[stix2.TLP_RED],
                                created_by_ref=self.identity["standard_id"],
                            )
                            objects.append(stix_relation_user)
                        if (
                            "match" in alert_details
                            and alert_details["match"] is not None
                            and "properties" in alert_details["match"]
                            and "file" in alert_details["match"]["properties"]
                        ):
                            file = alert_details["match"]["properties"]["file"]
                            hashes = {}
                            if "md5" in file:
                                hashes["MD5"] = file["md5"]
                            if "sha1" in file:
                                hashes["SHA-1"] = file["sha1"]
                            if "sha256" in file:
                                hashes["SHA-256"] = file["sha256"]
                            stix_file = stix2.File(
                                hashes=hashes,
                                object_marking_refs=[stix2.TLP_RED],
                                custom_properties={
                                    "created_by_ref": self.identity["standard_id"],
                                },
                            )
                            objects.append(stix_file)
                            stix_relation_file = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to", stix_file.id, stix_incident.id
                                ),
                                relationship_type="related-to",
                                source_ref=stix_file.id,
                                target_ref=stix_incident.id,
                                object_marking_refs=[stix2.TLP_RED],
                                created_by_ref=self.identity["standard_id"],
                            )
                            objects.append(stix_relation_file)
                        if intel["type"] == "processInjection":
                            stix_attack_pattern = stix2.AttackPattern(
                                id=AttackPattern.generate_id("T1055", "T1055"),
                                name="T1055",
                                allow_custom=True,
                                custom_properties={"x_mitre_id": "T1055"},
                            )
                            objects.append(stix_attack_pattern)
                            stix_relation_attack_pattern = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "uses", stix_incident.id, stix_attack_pattern.id
                                ),
                                relationship_type="uses",
                                source_ref=stix_incident.id,
                                target_ref=stix_attack_pattern.id,
                                object_marking_refs=[stix2.TLP_RED],
                                created_by_ref=self.identity["standard_id"],
                            )
                            objects.append(stix_relation_attack_pattern)
                        if (
                            "mitreAttack" in intel
                            and intel["mitreAttack"] is not None
                            and "techniques" in intel["mitreAttack"]
                        ):
                            for technique in intel["mitreAttack"]["techniques"]:
                                stix_attack_pattern = stix2.AttackPattern(
                                    id=AttackPattern.generate_id(
                                        technique["name"], technique["id"]
                                    ),
                                    name=technique["name"],
                                    allow_custom=True,
                                    custom_properties={"x_mitre_id": technique["id"]},
                                )
                                objects.append(stix_attack_pattern)
                                stix_relation_attack_pattern = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "uses", stix_incident.id, stix_attack_pattern.id
                                    ),
                                    relationship_type="uses",
                                    source_ref=stix_incident.id,
                                    target_ref=stix_attack_pattern.id,
                                    object_marking_refs=[stix2.TLP_RED],
                                    created_by_ref=self.identity["standard_id"],
                                )
                                objects.append(stix_relation_attack_pattern)

                    if len(objects) > 0:
                        stix_bundle = self.helper.stix2_create_bundle(objects)
                        friendly_name = (
                            "Tanium run @ "
                            + datetime.now().astimezone(pytz.UTC).isoformat()
                        )
                        work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id, friendly_name
                        )
                        self.helper.send_stix2_bundle(stix_bundle, work_id=work_id)
                        message = "Connector successfully run"
                        self.helper.api.work.to_processed(work_id, message)
            time.sleep(60)
