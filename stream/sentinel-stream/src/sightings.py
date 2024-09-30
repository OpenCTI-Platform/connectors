#################
# SIGHTINGS     #
#################
import json
import threading
import time
from datetime import datetime, timezone

import requests
import stix2
from dateutil.parser import parse
from pycti import (
    AttackPattern,
    CaseIncident,
    CustomObjectCaseIncident,
    CustomObservableHostname,
    Incident,
    StixCoreRelationship,
)

priorities = {
    "unknown": "P3",
    "informational": "P4",
    "low": "P3",
    "medium": "P2",
    "high": "P1",
    "unknownFutureValue": "P3",
}


class Sightings(threading.Thread):
    def __init__(
        self,
        helper,
        tenant_id,
        client_id,
        client_secret,
        resource_url,
        incident_url,
        target_product,
    ):
        threading.Thread.__init__(self)
        self.helper = helper
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.resource_url = resource_url
        self.incident_url = incident_url
        self.target_product = target_product
        self.header = None
        # Identity
        self.identity = self.helper.api.identity.create(
            type="System",
            name=self.helper.get_name(),
            description=self.helper.get_name(),
        )

    def _graph_api_authorization(self):
        try:
            url = (
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            )
            oauth_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            }
            response = requests.post(url, data=oauth_data)
            response_json = json.loads(response.text)
            oauth_token = response_json["access_token"]
            self.headers = {"Authorization": oauth_token}
        except Exception as e:
            raise ValueError("[ERROR] Failed generating oauth token {" + str(e) + "}")

    def run(self):
        self.helper.connector_logger.info(
            "[SIGHTINGS/INCIDENTS] Starting incident gatherer"
        )
        while True:
            self._graph_api_authorization()
            response = requests.get(
                self.resource_url + self.incident_url + "?$expand=alerts",
                headers=self.headers,
            )
            incidents = response.json()["value"] if "value" in response.json() else []
            state = self.helper.get_state()
            if state and "lastIncidentTimestamp" in state:
                last_timestamp = state["lastIncidentTimestamp"]
            else:
                last_timestamp = 0
            incidents = reversed(incidents)
            for incident in incidents:
                incident_timestamp = int(
                    round(parse(incident["lastUpdateDateTime"]).timestamp())
                )
                if (
                    int(incident_timestamp) > int(last_timestamp)
                    and incident["status"] != "resolved"
                ):
                    incident_date = parse(incident["createdDateTime"]).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    # Mark as processed
                    if state is not None:
                        state["lastIncidentTimestamp"] = incident_timestamp
                        self.helper.set_state(state)
                    else:
                        self.helper.set_state(
                            {"lastIncidentTimestamp": incident_timestamp}
                        )
                    # Create the bundle
                    case_objects = []
                    bundle_objects = []
                    # Check if the intel is in OpenCTI
                    # external_reference = self.helper.api.external_reference.read(
                    #    filters={
                    #        "mode": "and",
                    #        "filters": [
                    #            {"key": "source_name", "values": [self.target_product]},
                    #            {
                    #                "key": "external_id",
                    #                "values": [""],
                    #            },
                    #        ],
                    #        "filterGroups": [],
                    #    }
                    # )
                    # entity = None
                    # if external_reference is not None:
                    #                        entity = self.helper.api.stix_domain_object.read(
                    #        filters={
                    #            "mode": "and",
                    #            "filters": [
                    #                {
                    #                    "key": "hasExternalReference",
                    #                    "values": [external_reference["id"]],
                    #                }
                    #            ],
                    #            "filterGroups": [],
                    #        }
                    #    )
                    #    if entity is None:
                    #        entity = self.helper.api.stix_cyber_observable.read(
                    #             filters={
                    #                 "mode": "and",
                    #                 "filters": [
                    #                     {
                    #                         "key": "hasExternalReference",
                    #                         "values": [external_reference["id"]],
                    #                     }
                    #                 ],
                    #                 "filterGroups": [],
                    #             }
                    #        )
                    #    if entity is not None:
                    #        stix_sighting = stix2.Sighting(
                    #            id=StixSightingRelationship.generate_id(
                    #                entity["standard_id"],
                    #                self.identity["standard_id"],
                    #                alert_date,
                    #                alert_date,
                    #            ),
                    #            sighting_of_ref=entity["standard_id"],
                    #            where_sighted_refs=[self.identity["id"]],
                    #            count=1,
                    #            confidence=self.helper.connect_confidence_level,
                    #        )
                    #        objects.append(stix_sighting)
                    for alert in incident["alerts"]:
                        alert_date = parse(alert["createdDateTime"]).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        )
                        stix_incident = stix2.Incident(
                            id=Incident.generate_id(alert["title"], alert_date),
                            created=alert_date,
                            name=alert["title"],
                            description=alert["description"],
                            object_marking_refs=[stix2.TLP_RED],
                            created_by_ref=self.identity["standard_id"],
                            confidence=self.helper.connect_confidence_level,
                            external_references=[
                                {
                                    "source_name": self.target_product.replace(
                                        "Azure", "Microsoft"
                                    ),
                                    "url": alert["alertWebUrl"],
                                    "external_id": alert["id"],
                                }
                            ],
                            allow_custom=True,
                            custom_properties={
                                "source": self.target_product.replace(
                                    "Azure", "Microsoft"
                                ),
                                "severity": alert["severity"],
                                "incident_type": "alert",
                            },
                        )
                        case_objects.append(stix_incident)
                        bundle_objects.append(stix_incident)
                        for technique in alert["mitreTechniques"]:
                            stix_attack_pattern = stix2.AttackPattern(
                                id=AttackPattern.generate_id(technique, technique),
                                name=technique,
                                allow_custom=True,
                                custom_properties={"x_mitre_id": technique},
                            )
                            case_objects.append(stix_attack_pattern)
                            bundle_objects.append(stix_attack_pattern)
                            stix_relation_attack_pattern = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "uses", stix_incident.id, stix_attack_pattern.id
                                ),
                                relationship_type="uses",
                                source_ref=stix_incident.id,
                                target_ref=stix_attack_pattern.id,
                                created_by_ref=self.identity["standard_id"],
                            )
                            case_objects.append(stix_relation_attack_pattern)
                            bundle_objects.append(stix_relation_attack_pattern)
                        for evidence in alert["evidence"]:
                            if (
                                evidence["@odata.type"]
                                == "#microsoft.graph.security.userEvidence"
                            ):
                                stix_account = stix2.UserAccount(
                                    account_login=evidence["userAccount"][
                                        "accountName"
                                    ],
                                    display_name=evidence["userAccount"]["displayName"],
                                    object_marking_refs=[stix2.TLP_RED],
                                    custom_properties={
                                        "created_by_ref": self.identity["standard_id"],
                                    },
                                )
                                case_objects.append(stix_account)
                                bundle_objects.append(stix_account)
                                stix_relation_account = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "related-to", stix_account.id, stix_incident.id
                                    ),
                                    relationship_type="related-to",
                                    source_ref=stix_account.id,
                                    target_ref=stix_incident.id,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                case_objects.append(stix_relation_account)
                                bundle_objects.append(stix_relation_account)
                            if (
                                evidence["@odata.type"]
                                == "#microsoft.graph.security.ipEvidence"
                            ):
                                stix_ip = stix2.IPv4Address(
                                    value=evidence["ipAddress"],
                                    object_marking_refs=[stix2.TLP_RED],
                                    custom_properties={
                                        "created_by_ref": self.identity["standard_id"],
                                    },
                                )
                                case_objects.append(stix_ip)
                                bundle_objects.append(stix_ip)
                                stix_relation_ip = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "related-to", stix_ip.id, stix_incident.id
                                    ),
                                    relationship_type="related-to",
                                    source_ref=stix_ip.id,
                                    target_ref=stix_incident.id,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                case_objects.append(stix_relation_ip)
                                bundle_objects.append(stix_relation_ip)
                            if (
                                evidence["@odata.type"]
                                == "#microsoft.graph.security.urlEvidence"
                            ):
                                stix_url = stix2.URL(
                                    value=evidence["url"],
                                    object_marking_refs=[stix2.TLP_RED],
                                    custom_properties={
                                        "created_by_ref": self.identity["standard_id"],
                                    },
                                )
                                case_objects.append(stix_url)
                                bundle_objects.append(stix_url)
                                stix_relation_url = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "related-to", stix_url.id, stix_incident.id
                                    ),
                                    relationship_type="related-to",
                                    source_ref=stix_url.id,
                                    target_ref=stix_incident.id,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                case_objects.append(stix_relation_url)
                                bundle_objects.append(stix_relation_url)
                            if (
                                evidence["@odata.type"]
                                == "#microsoft.graph.security.deviceEvidence"
                            ):
                                stix_hostname = CustomObservableHostname(
                                    value=evidence["deviceDnsName"],
                                    object_marking_refs=[stix2.TLP_RED],
                                    custom_properties={
                                        "created_by_ref": self.identity["standard_id"],
                                    },
                                )
                                case_objects.append(stix_hostname)
                                bundle_objects.append(stix_hostname)
                                stix_relation_hostname = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "related-to", stix_hostname.id, stix_incident.id
                                    ),
                                    relationship_type="related-to",
                                    source_ref=stix_hostname.id,
                                    target_ref=stix_incident.id,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                case_objects.append(stix_relation_hostname)
                                bundle_objects.append(stix_relation_hostname)
                            if (
                                evidence["@odata.type"]
                                == "#microsoft.graph.security.processEvidence"
                            ):
                                file = evidence["imageFile"]
                                hashes = {}
                                if "md5" in file:
                                    hashes["MD5"] = file["md5"]
                                if "sha1" in file:
                                    hashes["SHA-1"] = file["sha1"]
                                if "sha256" in file:
                                    hashes["SHA-256"] = file["sha256"]
                                stix_file = stix2.File(
                                    hashes=hashes,
                                    name=file["fileName"],
                                    size=file["fileSize"],
                                    object_marking_refs=[stix2.TLP_RED],
                                    custom_properties={
                                        "created_by_ref": self.identity["standard_id"],
                                    },
                                )
                                case_objects.append(stix_file)
                                bundle_objects.append(stix_file)
                                stix_relation_file = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "related-to", stix_file.id, stix_incident.id
                                    ),
                                    relationship_type="related-to",
                                    source_ref=stix_file.id,
                                    target_ref=stix_incident.id,
                                    created_by_ref=self.identity["standard_id"],
                                )
                                case_objects.append(stix_relation_file)
                                bundle_objects.append(stix_relation_file)

                    stix_case = CustomObjectCaseIncident(
                        id=CaseIncident.generate_id(
                            incident["displayName"], incident_date
                        ),
                        name=incident["displayName"],
                        description="Incident from "
                        + self.target_product.replace("Azure", "Microsoft")
                        + " | classification: "
                        + incident["classification"]
                        + " | determination: "
                        + incident["determination"],
                        severity=incident["severity"],
                        priority=priorities[incident["severity"]],
                        created=incident_date,
                        external_references=[
                            {
                                "source_name": self.target_product.replace(
                                    "Azure", "Microsoft"
                                ),
                                "external_id": incident["id"],
                                "url": incident["incidentWebUrl"],
                            }
                        ],
                        confidence=self.helper.connect_confidence_level,
                        created_by_ref=self.identity["standard_id"],
                        object_marking_refs=[stix2.TLP_RED],
                        object_refs=bundle_objects,
                    )
                    bundle_objects.append(stix_case)

                    if len(bundle_objects) > 0:
                        stix_bundle = self.helper.stix2_create_bundle(bundle_objects)
                        now = datetime.now(tz=timezone.utc)
                        friendly_name = "Sentinel run @ " + now.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                        work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id, friendly_name
                        )
                        self.helper.send_stix2_bundle(stix_bundle, work_id=work_id)
                        message = "Connector successfully run"
                        self.helper.api.work.to_processed(work_id, message)
            time.sleep(60)
