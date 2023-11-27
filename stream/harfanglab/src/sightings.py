#################
# SIGHTINGS     #
#################

import json
import re
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
    Indicator,
    Note,
    StixCoreRelationship,
    StixSightingRelationship,
)


class Sightings(threading.Thread):
    def __init__(
        self,
        helper,
        harfanglab_ssl_verify,
        harfanglab_url,
        headers,
        harfanglab_source_list_name,
        harfanglab_import_security_events_as_incidents,
        harfanglab_import_security_events_filters_by_status,
        harfanglab_import_filters_by_alert_type,
        harfanglab_import_threats_as_case_incidents,
        harfanglab_default_markings,
        harfanglab_rule_maturity,
    ):
        threading.Thread.__init__(self)
        self.helper = helper
        self.headers = headers
        self.harfanglab_url = harfanglab_url
        self.api_url = harfanglab_url + "/api/data"
        self.source_list_name = harfanglab_source_list_name
        self.ssl_verify = harfanglab_ssl_verify
        self.import_security_events_as_incidents = (
            harfanglab_import_security_events_as_incidents
        )
        self.import_security_events_filters_by_status = (
            harfanglab_import_security_events_filters_by_status
        )
        self.import_filters_by_alert_type = harfanglab_import_filters_by_alert_type
        self.import_threats_as_case_incidents = (
            harfanglab_import_threats_as_case_incidents
        )
        self.default_markings = harfanglab_default_markings
        self.harfanglab_rule_maturity = harfanglab_rule_maturity
        self.list_info = {}

        # Identity
        self.identity = self.helper.api.identity.create(
            type="System",
            name=self.helper.get_name(),
            description=f"System {self.helper.get_name()}",
        )

    def run(self):
        while True:
            if (
                self.import_threats_as_case_incidents is False
                and self.import_security_events_as_incidents is True
            ):
                self.helper.log_info("[INCIDENTS] Starting alerts gatherer")
                self.create_incident()
                self.helper.log_info(
                    "[INCIDENTS] Incidents creations completed successfully"
                )

            elif self.import_threats_as_case_incidents is True:
                self.helper.log_info(
                    "[INCIDENTS/CASE-INCIDENTS] Starting alerts gatherer"
                )
                self.create_incident()
                self.helper.log_info(
                    "[INCIDENTS] Incidents creations completed successfully"
                )
                self.create_case_incident()
                self.helper.log_info(
                    "[CASE-INCIDENTS] Case-Incidents creations completed successfully"
                )

            time.sleep(60)

    def create_incident(self):
        alert_filtered = self.get_alerts_filtered()
        alerts_filtered_total_count = int(alert_filtered["count"])
        alerts_filtered = self.get_alerts_filtered(alerts_filtered_total_count)

        convert_marking_for_stix2 = self.handle_marking()

        # Create the bundle stix
        bundle_objects = []

        all_sightings_objects = []
        all_incidents_objects = []
        all_indicators_objects = []
        all_observable_objects = []
        all_hostnames_objects = []
        all_users_objects = []
        all_observables_directories = []

        for alert in alerts_filtered["results"]:
            new_alert_built = self.build_alert_object(alert)

            if new_alert_built["alert_type"] == "ioc":
                msg_parsed = self.msg_parser(new_alert_built)
                if msg_parsed is None:
                    self.helper.log_error(
                        "[ERROR] An error occurred while parsing msg."
                    )
                    continue

                alert_create_date = new_alert_built["created_at"]
                if "updated_at" in new_alert_built:
                    alert_update_date = new_alert_built["updated_at"]
                else:
                    alert_update_date = new_alert_built["created_at"]

                indicators_ioc_info = self._query(
                    f"/threat_intelligence/IOCRule/?value={msg_parsed}"
                )
                indicator_matching = self.get_match(
                    indicators_ioc_info["results"], "value", msg_parsed
                )

                # If the indicator does not exist or no longer exists at HarfangLab
                if not indicators_ioc_info["results"]:
                    self.helper.log_error(
                        "[ERROR] The rule that was triggered does not exist or no longer exists at HarfangLab."
                    )
                    continue
                else:
                    # Generate incident
                    build_observable_hashes = []
                    if indicators_ioc_info["results"] and indicator_matching[
                        "type"
                    ] in ["filename", "filepath"]:
                        incident_name = (
                            new_alert_built["process"]["hashes"]["sha256"]
                            + " on "
                            + new_alert_built["agent"]["hostname"]
                        )

                    elif (
                        indicators_ioc_info["results"]
                        and indicator_matching["type"] == "hash"
                    ):
                        incident_name = ""
                        search_observables = self.helper.api.stix_cyber_observable.list(
                            search=indicator_matching["value"]
                        )
                        observable_matching = self.get_match(
                            search_observables,
                            "observable_value",
                            indicator_matching["value"],
                        )

                        if search_observables and observable_matching:
                            incident_name = (
                                observable_matching["observable_value"]
                                + " on "
                                + new_alert_built["agent"]["hostname"]
                            )
                            for search_observable in search_observables:
                                if "hashes" in search_observable:
                                    if "name" in search_observable:
                                        build_observable_hashes.append(
                                            {"name": search_observable["name"]}
                                        )
                                    for observable_hash in search_observable["hashes"]:
                                        if (
                                            "SHA-256" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes.append(
                                                {"SHA-256": observable_hash["hash"]}
                                            )
                                        if (
                                            "SHA-1" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes.append(
                                                {"SHA-1": observable_hash["hash"]}
                                            )
                                        if (
                                            "MD5" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes.append(
                                                {"MD5": observable_hash["hash"]}
                                            )

                        elif search_observables and not observable_matching:
                            for search_observable in search_observables:
                                if "hashes" in search_observable:
                                    if "name" in search_observable:
                                        build_observable_hashes.append(
                                            {"name": search_observable["name"]}
                                        )
                                    for observable_hash in search_observable["hashes"]:
                                        if (
                                            "SHA-256" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes.append(
                                                {"SHA-256": observable_hash["hash"]}
                                            )
                                        if (
                                            "SHA-1" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes.append(
                                                {"SHA-1": observable_hash["hash"]}
                                            )
                                        if (
                                            "MD5" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes.append(
                                                {"MD5": observable_hash["hash"]}
                                            )
                                        if (
                                            observable_hash["hash"]
                                            == indicator_matching["value"]
                                        ):
                                            incident_name = (
                                                search_observable["observable_value"]
                                                + " on "
                                                + new_alert_built["agent"]["hostname"]
                                            )
                    else:
                        incident_name = (
                            msg_parsed + " on " + new_alert_built["agent"]["hostname"]
                        )

                    stix_incident = stix2.Incident(
                        id=Incident.generate_id(incident_name, alert_create_date),
                        created=alert_create_date,
                        name=incident_name,
                        description=f"{new_alert_built['msg']}",
                        object_marking_refs=[convert_marking_for_stix2],
                        created_by_ref=self.identity["standard_id"],
                        confidence=self.helper.connect_confidence_level,
                        external_references=[
                            {
                                "source_name": "HarfangLab - Security Events",
                                "url": f"{self.harfanglab_url}/security-event/{new_alert_built['url_id']}/summary",
                                "external_id": new_alert_built["url_id"],
                            }
                        ],
                        allow_custom=True,
                        custom_properties={
                            "source": "HarfangLab",
                            "severity": new_alert_built["level"],
                            "incident_type": "alert",
                            "first_seen": alert_create_date,
                            "last_seen": alert_update_date,
                        },
                    )
                    all_incidents_objects.append(stix_incident)

                    # -------------------------------
                    # Create indicator and observable
                    # -------------------------------
                    self.helper.log_info(
                        "[CREATE] Creating STIX indicator, observable and relationship"
                    )

                    # Create indicator
                    indicator_convert_type = self.stix_convert_type(
                        indicator_matching["type"], indicator_matching["value"]
                    )

                    if indicator_convert_type is not None:
                        indicator_name = ""
                        indicator_pattern = ""
                        full_observable_hashes = None

                        hash_existing = False
                        if indicator_matching["type"] == "hash":
                            for build_hash in build_observable_hashes:
                                for key, value in build_hash.items():
                                    if value == indicator_matching["value"]:
                                        hash_existing = True

                        if indicator_matching["type"] in ["filename", "filepath"]:
                            if indicator_convert_type == "file:name":
                                indicator_pattern = (
                                    f"[file:hashes.'SHA-256' = '{new_alert_built['process']['hashes']['sha256']}' AND "
                                    f"file:hashes.MD5 = '{new_alert_built['process']['hashes']['md5']}' AND "
                                    f"file:hashes.'SHA-1' = '{new_alert_built['process']['hashes']['sha1']}']"
                                )

                                indicator_name = new_alert_built["process"]["hashes"][
                                    "sha256"
                                ]
                                full_observable_hashes = {
                                    "SHA-256": new_alert_built["process"]["hashes"][
                                        "sha256"
                                    ],
                                    "SHA-1": new_alert_built["process"]["hashes"][
                                        "sha1"
                                    ],
                                    "MD5": new_alert_built["process"]["hashes"]["md5"],
                                }

                            observable_name = new_alert_built["process"]["process_name"]
                            observable_directory = new_alert_built["process"][
                                "current_directory"
                            ]

                            # Create observable directory
                            stix_observable_directory = stix2.Directory(
                                path=observable_directory,
                                object_marking_refs=[convert_marking_for_stix2],
                                custom_properties={
                                    "created_by_ref": self.identity["standard_id"],
                                },
                            )
                            all_observables_directories.append(
                                {
                                    "incident_id": stix_incident["id"],
                                    "stix_directory": stix_observable_directory,
                                }
                            )

                        elif hash_existing is False:
                            observable_name = indicator_matching["value"]
                            indicator_name = indicator_matching["value"]
                            indicator_pattern = f"[{indicator_convert_type} = '{indicator_matching['value']}']"
                        else:
                            observable_name = new_alert_built["process"]["process_name"]
                            indicator_name = new_alert_built["process"]["hashes"][
                                "sha256"
                            ]
                            indicator_pattern = (
                                f"[file:hashes.'SHA-256' = '{new_alert_built['process']['hashes']['sha256']}' AND "
                                f"file:hashes.MD5 = '{new_alert_built['process']['hashes']['md5']}' AND "
                                f"file:hashes.'SHA-1' = '{new_alert_built['process']['hashes']['sha1']}']"
                            )

                        stix_indicator = stix2.Indicator(
                            id=Indicator.generate_id(indicator_matching["value"]),
                            created_by_ref=self.identity["standard_id"],
                            created=indicator_matching["creation_date"],
                            modified=indicator_matching["last_update"],
                            name=indicator_name,
                            pattern=indicator_pattern,
                            description=indicator_matching["description"],
                            object_marking_refs=[convert_marking_for_stix2],
                            custom_properties={
                                "pattern_type": "stix",
                                "x_opencti_score": self.helper.connect_confidence_level,
                                "detection": True,
                            },
                        )
                        all_indicators_objects.append(stix_indicator)

                        # Generate sighting : indicator -> type "sigthed in/at" -> system
                        stix_sighting = self.process_create_sighting_relationship(
                            new_alert_built,
                            stix_indicator["id"],
                            convert_marking_for_stix2,
                        )
                        all_sightings_objects.append(stix_sighting)

                        # Create observable
                        stix_observable = self.create_stix_observable(
                            convert_marking_for_stix2,
                            indicator_convert_type,
                            indicator_name,
                            observable_name,
                            full_observable_hashes,
                            build_observable_hashes,
                        )
                        all_observable_objects.append(stix_observable)

                    else:
                        self.helper.log_error(
                            "[ERROR] The triggered rule was not correctly identified and the conversion of the type attribute failed."
                        )

                    # Create Observable Hostname
                    stix_hostname = CustomObservableHostname(
                        value=new_alert_built["agent"]["hostname"],
                        object_marking_refs=[convert_marking_for_stix2],
                        custom_properties={
                            "created_by_ref": self.identity["standard_id"],
                        },
                    )
                    all_hostnames_objects.append(stix_hostname)

                    # Create Observable User Account
                    stix_user = stix2.UserAccount(
                        account_login=new_alert_built["process"]["username"],
                        object_marking_refs=[convert_marking_for_stix2],
                        custom_properties={
                            "created_by_ref": self.identity["standard_id"],
                        },
                    )
                    all_users_objects.append(stix_user)
            if new_alert_built["alert_type"] == "sigma":
                #     prepare_rule_name_for_search = new_alert_built["rule_name"].replace(" ", "%20")
                #     indicators_sigma_info = self._query(f"/threat_intelligence/SigmaRule/?search={prepare_rule_name_for_search}")
                #
                #     sigma_rule = []
                #
                #     for indicator in indicators_sigma_info["results"]:
                #         if new_alert_built["rule_name"] == indicator["rule_name"] and new_alert_built["msg"] == indicator["rule_description"]:
                #             sigma_rule.append(indicator)
                continue

            if new_alert_built["alert_type"] == "yara":
                continue

        list_of_directories = all_observables_directories.copy()
        for observable_directory in list_of_directories:
            bundle_objects.append(observable_directory["stix_directory"])

        list_of_sightings_unique = self.sort_object_unique(all_sightings_objects, "id")
        # list_of_incidents_unique = self.sort_object_unique(all_incidents_objects, "id")

        list_of_observables_unique = self.sort_object_unique(
            all_observable_objects, "id"
        )
        for observable in list_of_observables_unique:
            bundle_objects.append(observable)

        list_of_indicators_unique = self.sort_object_unique(
            all_indicators_objects, "id"
        )
        for indicator in list_of_indicators_unique:
            bundle_objects.append(indicator)

        list_of_hostnames_unique = self.sort_object_unique(
            all_hostnames_objects, "value"
        )
        for observable_hostname in list_of_hostnames_unique:
            bundle_objects.append(observable_hostname)

        list_of_users_unique = self.sort_object_unique(
            all_users_objects, "account_login"
        )
        for observable_user in list_of_users_unique:
            bundle_objects.append(observable_user)

        for indicator_unique in list_of_indicators_unique:
            for observable_unique in list_of_observables_unique:
                if observable_unique["type"] == "file":
                    if "SHA-256" in observable_unique["hashes"]:
                        if (
                            indicator_unique["name"]
                            == observable_unique["hashes"]["SHA-256"]
                        ):
                            # Generate relationship : indicator -> type "based-on" -> observable
                            stix_relation_new_observable = (
                                self.process_stix_relationship(
                                    "based-on",
                                    indicator_unique["id"],
                                    observable_unique["id"],
                                    convert_marking_for_stix2,
                                )
                            )
                            bundle_objects.append(stix_relation_new_observable)

                    elif "SHA-1" in observable_unique["hashes"]:
                        if (
                            indicator_unique["name"]
                            == observable_unique["hashes"]["SHA-1"]
                        ):
                            # Generate relationship : indicator -> type "based-on" -> observable
                            stix_relation_new_observable = (
                                self.process_stix_relationship(
                                    "based-on",
                                    indicator_unique["id"],
                                    observable_unique["id"],
                                    convert_marking_for_stix2,
                                )
                            )
                            bundle_objects.append(stix_relation_new_observable)

                    elif "MD5" in observable_unique["hashes"]:
                        if (
                            indicator_unique["name"]
                            == observable_unique["hashes"]["MD5"]
                        ):
                            # Generate relationship : indicator -> type "based-on" -> observable
                            stix_relation_new_observable = (
                                self.process_stix_relationship(
                                    "based-on",
                                    indicator_unique["id"],
                                    observable_unique["id"],
                                    convert_marking_for_stix2,
                                )
                            )
                            bundle_objects.append(stix_relation_new_observable)

                else:
                    if indicator_unique["name"] == observable_unique["value"]:
                        # Generate relationship : indicator -> type "based-on" -> observable
                        stix_relation_new_observable = self.process_stix_relationship(
                            "based-on",
                            indicator_unique["id"],
                            observable_unique["id"],
                            convert_marking_for_stix2,
                        )
                        bundle_objects.append(stix_relation_new_observable)

        global_incidents = self.handling_of_incidents_and_external_references(
            all_incidents_objects
        )
        for global_item in global_incidents:
            bundle_objects.append(global_item)

            if global_item["type"] == "incident":
                for indicator_unique in list_of_indicators_unique:
                    indicator_name = str(indicator_unique["name"])
                    incident_name = str(global_item["name"])
                    check = incident_name.startswith(indicator_name)

                    if check is True:
                        # Generate relationship : indicator -> type "indicates" -> incident
                        stix_relation_new_indicator = self.process_stix_relationship(
                            "indicates",
                            indicator_unique["id"],
                            global_item["id"],
                            convert_marking_for_stix2,
                        )
                        bundle_objects.append(stix_relation_new_indicator)
                for observable_directory in all_observables_directories:
                    if observable_directory["incident_id"] == global_item["id"]:
                        bundle_objects.append(observable_directory["stix_directory"])

                        # Generate relationship : observable (Directory) -> type "related-to" -> incident
                        stix_relation_observable_directory = (
                            self.process_stix_relationship(
                                "related-to",
                                observable_directory["stix_directory"]["id"],
                                global_item["id"],
                                convert_marking_for_stix2,
                            )
                        )
                        bundle_objects.append(stix_relation_observable_directory)
                for observable_unique in list_of_observables_unique:
                    if observable_unique["type"] == "file":
                        check = False
                        if "SHA-256" in observable_unique["hashes"]:
                            observable_name = str(
                                observable_unique["hashes"]["SHA-256"]
                            )
                            incident_name = str(global_item["name"])
                            check = incident_name.startswith(observable_name)
                        elif "SHA-1" in observable_unique["hashes"]:
                            observable_name = str(observable_unique["hashes"]["SHA-1"])
                            incident_name = str(global_item["name"])
                            check = incident_name.startswith(observable_name)
                        elif "MD5" in observable_unique["hashes"]:
                            observable_name = str(observable_unique["hashes"]["MD5"])
                            incident_name = str(global_item["name"])
                            check = incident_name.startswith(observable_name)
                    else:
                        observable_name = str(observable_unique["value"])
                        incident_name = str(global_item["name"])
                        check = incident_name.startswith(observable_name)

                    if check is True:
                        # Generate relationship : observable -> type "related-to" -> incident
                        stix_relation_new_observable = self.process_stix_relationship(
                            "related-to",
                            observable_unique["id"],
                            global_item["id"],
                            convert_marking_for_stix2,
                        )
                        bundle_objects.append(stix_relation_new_observable)

                # Generate relationship : Hostname -> type "related-to" -> incident
                stix_relation_hostname = self.process_stix_relationship(
                    "related-to",
                    list_of_hostnames_unique[0]["id"],
                    global_item["id"],
                    convert_marking_for_stix2,
                )
                bundle_objects.append(stix_relation_hostname)

                # Generate relationship : User -> type "related-to" -> incident
                stix_relation_user = self.process_stix_relationship(
                    "related-to",
                    list_of_users_unique[0]["id"],
                    global_item["id"],
                    convert_marking_for_stix2,
                )
                bundle_objects.append(stix_relation_user)

        global_sightings = self.handling_of_sightings_and_external_references(
            list_of_sightings_unique
        )
        for global_sighting in global_sightings:
            bundle_objects.append(global_sighting)

        # Sort final Bundle objects
        # list_bundle_unique = self.sort_object_unique(bundle_objects, "id")

        self.generate_stix_bundle(bundle_objects)
        self.list_info = {
            "bundle_objects": bundle_objects,
            "list_of_users": list_of_users_unique,
            "list_of_sightings": all_sightings_objects,
            "list_of_incidents": all_incidents_objects,
            "list_of_indicators": list_of_indicators_unique,
            "list_of_observables": list_of_observables_unique,
            "list_of_hostnames": list_of_hostnames_unique,
            "list_of_directories": list_of_directories,
        }
        return

    def create_case_incident(self):
        list_info = self.list_info
        threats = self._query("/alert/alert/Threat")

        convert_marking_for_stix2 = self.handle_marking()

        bundle_objects = []
        priorities = {
            "critical": "P1",
            "high": "P2",
            "medium": "P3",
            "low": "P4",
        }

        bundle_incidents = []
        bundle_sightings = []
        bundle_indicators = []
        bundle_relationships = []
        bundle_agents = []
        bundle_observables = []

        for bundle in list_info["bundle_objects"]:
            if bundle["type"] == "incident":
                bundle_incidents.append(bundle)
            elif bundle["type"] == "sighting":
                bundle_sightings.append(bundle)
            elif bundle["type"] == "indicator":
                bundle_indicators.append(bundle)
            elif bundle["type"] == "relationship":
                bundle_relationships.append(bundle)
            elif bundle["type"] == "hostname" or bundle["type"] == "user-account":
                bundle_agents.append(bundle)
            else:
                bundle_observables.append(bundle)

        for threat in threats["results"]:
            case_incident_date = parse(threat["first_seen"]).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

            list_of_references_alerts = self.alerts_in_case_incident(
                bundle_observables, threat["id"]
            )

            if list_of_references_alerts is None or not list_of_references_alerts:
                continue
            else:
                merge_all_references = []

                # Add observables linked to the threat (case incident) in the merge_all_references
                list_of_references_alerts_unique = self.sort_object_unique(
                    list_of_references_alerts, "id"
                )
                for reference_observable in list_of_references_alerts_unique:
                    merge_all_references.append(reference_observable)

                    # Add incidents linked to the threat (case incident) in the merge_all_references
                    for bundle_incident in bundle_incidents:
                        if reference_observable["type"] == "file":
                            if "SHA-256" in reference_observable["hashes"]:
                                if bundle_incident["name"].startswith(
                                    reference_observable["hashes"]["SHA-256"]
                                ):
                                    merge_all_references.append(bundle_incident)

                            if "SHA-1" in reference_observable["hashes"]:
                                if bundle_incident["name"].startswith(
                                    reference_observable["hashes"]["SHA-1"]
                                ):
                                    merge_all_references.append(bundle_incident)

                            if "MD5" in reference_observable["hashes"]:
                                if bundle_incident["name"].startswith(
                                    reference_observable["hashes"]["MD5"]
                                ):
                                    merge_all_references.append(bundle_incident)

                        elif reference_observable["type"] == "directory":
                            if bundle_incident["name"].startswith(
                                reference_observable["linked_to"]
                            ):
                                merge_all_references.append(bundle_incident)

                        elif bundle_incident["name"].startswith(
                            reference_observable["value"]
                        ):
                            merge_all_references.append(bundle_incident)

                # Add agent (hostname and user) linked to the threat (case incident) in the merge_all_references
                for bundle_agent in bundle_agents:
                    if bundle_agent["type"] == "hostname":
                        if (
                            bundle_agent["value"]
                            == threat["top_agents"][0]["agent_hostname"]
                        ):
                            merge_all_references.append(bundle_agent)

                    elif bundle_agent["type"] == "user-account":
                        if (
                            bundle_agent["account_login"]
                            == threat["top_impacted_users"][0]["user_name"]
                        ):
                            merge_all_references.append(bundle_agent)
                    else:
                        continue

                # Add relationships (incident and observable) linked to the threat (case incident) in the merge_all_references
                for reference in merge_all_references:
                    if reference["type"] == "incident":
                        for bundle_relationship in bundle_relationships:
                            if reference["id"] == bundle_relationship["target_ref"]:
                                merge_all_references.append(bundle_relationship)
                    else:
                        continue

                all_mitre_tactics = []

                for mitre_tactic_name, mitre_tactic_value in threat[
                    "mitre_tactics"
                ].items():
                    all_mitre_tactics.append(mitre_tactic_name)

                if not all_mitre_tactics:
                    description = ""
                else:
                    str_mitre_tactics = ", ".join(map(str, all_mitre_tactics))
                    description = "Mitre Tactics : " + str_mitre_tactics

                stix_case_incident = CustomObjectCaseIncident(
                    id=CaseIncident.generate_id(threat["slug"], case_incident_date),
                    name=f"{threat['slug']} on {threat['top_agents'][0]['agent_hostname']}",
                    description=description,
                    severity=threat["level"],
                    priority=priorities[threat["level"]],
                    created=case_incident_date,
                    external_references=[
                        {
                            "source_name": "HarfangLab - Threats",
                            "url": f"{self.harfanglab_url}/threat/{threat['id']}/summary",
                            "external_id": threat["id"],
                        }
                    ],
                    confidence=self.helper.connect_confidence_level,
                    created_by_ref=self.identity["standard_id"],
                    object_marking_refs=[convert_marking_for_stix2],
                    object_refs=[x["id"] for x in merge_all_references],
                )
                bundle_objects.append(stix_case_incident)

                # Generate stix Note
                stix_note = self.create_note(
                    threat, convert_marking_for_stix2, stix_case_incident
                )
                if stix_note is not None:
                    bundle_objects.append(stix_note)

        self.generate_stix_bundle(bundle_objects)
        return

    def create_note(self, threat, marking, case_incident):
        threat_note = self._query(f"/alert/alert/Threat/{threat['id']}/note")

        if threat_note is not None and threat_note != "":
            note_date = parse(threat_note["creation_date"]).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

            return stix2.Note(
                id=Note.generate_id(threat_note["title"], note_date),
                confidence=self.helper.connect_confidence_level,
                created=threat_note["creation_date"],
                modified=threat_note["last_update"],
                created_by_ref=self.identity["standard_id"],
                object_marking_refs=marking,
                abstract=f"Linked to {threat_note['title']}",
                content=threat_note["content"],
                object_refs=[case_incident["id"]],
                allow_custom=True,
                external_references=[
                    {
                        "source_name": "HarfangLab - Threats",
                        "url": f"{self.harfanglab_url}/threat/{threat['id']}/summary",
                        "external_id": threat["id"],
                    }
                ],
            )

    def handling_of_sightings_and_external_references(self, list_of_sightings_unique):
        new_object = {}
        for sighting_sorted_by_ref in list_of_sightings_unique:
            if sighting_sorted_by_ref["sighting_of_ref"] not in new_object:
                new_object[sighting_sorted_by_ref["sighting_of_ref"]] = []
            new_object[sighting_sorted_by_ref["sighting_of_ref"]].append(
                sighting_sorted_by_ref
            )

        global_sightings = []

        for indicator_id, sightings in new_object.items():
            external_references = []

            for sighting in sightings:
                external_references.extend(sighting["external_references"])

            alert_date = datetime.strftime(sighting["created"], "%Y-%m-%dT%H:%M:%SZ")

            global_sightings_relationship = stix2.Sighting(
                id=StixSightingRelationship.generate_id(
                    sighting["sighting_of_ref"],
                    self.identity["id"],
                    alert_date,
                    alert_date,
                ),
                first_seen=sighting["first_seen"],
                last_seen=sighting["last_seen"],
                count=int(len(external_references)),
                sighting_of_ref=sighting["sighting_of_ref"],
                where_sighted_refs=[self.identity["standard_id"]],
                confidence=self.helper.connect_confidence_level,
                object_marking_refs=sighting["object_marking_refs"],
                external_references=external_references,
                custom_properties={
                    "x_opencti_negative": sighting["x_opencti_negative"],
                },
            )
            global_sightings.append(global_sightings_relationship)

        return global_sightings

    def handling_of_incidents_and_external_references(self, list_of_incidents_unique):
        global_incidents = []
        incidents_sorted_by_date = sorted(
            list_of_incidents_unique, key=lambda x: x["created"]
        )

        new_object = {}
        for incident_sorted_by_date in incidents_sorted_by_date:
            if incident_sorted_by_date["name"] not in new_object:
                new_object[incident_sorted_by_date["name"]] = []
            new_object[incident_sorted_by_date["name"]].append(incident_sorted_by_date)

        prepare_incidents_uniques = []

        for incident_name, incidents_values in new_object.items():
            external_references = []
            object_last_updated_incident = incidents_values[0]

            for incident_value in incidents_values:
                external_references.append(incident_value["external_references"][0])

            prepare_incident_built = {
                "name": incident_name,
                "all_external_references": external_references,
                "object_last_updated_incident": object_last_updated_incident,
            }
            prepare_incidents_uniques.append(prepare_incident_built)

        for incident_unique in prepare_incidents_uniques:
            global_incidents_unique = stix2.Incident(
                id=Incident.generate_id(
                    incident_unique["name"],
                    incident_unique["object_last_updated_incident"]["first_seen"],
                ),
                created=incident_unique["object_last_updated_incident"]["first_seen"],
                name=incident_unique["name"],
                description=incident_unique["object_last_updated_incident"][
                    "description"
                ],
                object_marking_refs=incident_unique["object_last_updated_incident"][
                    "object_marking_refs"
                ],
                created_by_ref=self.identity["standard_id"],
                confidence=self.helper.connect_confidence_level,
                external_references=incident_unique["all_external_references"],
                allow_custom=True,
                custom_properties={
                    "source": "HarfangLab",
                    "severity": incident_unique["object_last_updated_incident"][
                        "severity"
                    ],
                    "incident_type": "alert",
                    "first_seen": incident_unique["object_last_updated_incident"][
                        "first_seen"
                    ],
                    "last_seen": incident_unique["object_last_updated_incident"][
                        "last_seen"
                    ],
                },
            )
            global_incidents.append(global_incidents_unique)

        return global_incidents

    def process_create_sighting_relationship(self, new_alert_built, indicator, marking):
        alert_date = parse(new_alert_built["created_at"]).strftime("%Y-%m-%dT%H:%M:%SZ")

        if new_alert_built["status"] == "false_positive":
            is_status_false_positive = True
        else:
            is_status_false_positive = False

        if "updated_at" not in new_alert_built:
            new_alert_built["updated_at"] = new_alert_built["created_at"]

        return stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                indicator,
                self.identity["id"],
                alert_date,
                alert_date,
            ),
            first_seen=new_alert_built["created_at"],
            last_seen=new_alert_built["updated_at"],
            sighting_of_ref=indicator,
            where_sighted_refs=[self.identity["standard_id"]],
            count=1,
            confidence=self.helper.connect_confidence_level,
            object_marking_refs=marking,
            external_references=[
                {
                    "source_name": "HarfangLab - Security Events",
                    "url": f"{self.harfanglab_url}/security-event/{new_alert_built['url_id']}/summary",
                    "external_id": new_alert_built["url_id"],
                }
            ],
            custom_properties={
                "x_opencti_negative": is_status_false_positive,
            },
        )

    def create_stix_observable(
        self,
        marking,
        observable_type,
        observable_value,
        observable_name,
        full_observable_hashes=None,
        build_observable_hashes=None,
    ):
        if observable_type in [
            "file:hashes.'SHA-256'",
            "file:hashes.MD5",
            "file:hashes.'SHA-1'",
        ]:
            hashes = {}
            if build_observable_hashes:
                return stix2.File(
                    name=build_observable_hashes[0]["name"],
                    hashes={
                        "SHA-256": build_observable_hashes[1]["SHA-256"],
                        "SHA-1": build_observable_hashes[2]["SHA-1"],
                        "MD5": build_observable_hashes[3]["MD5"],
                    },
                    object_marking_refs=[marking],
                    custom_properties={
                        "created_by_ref": self.identity["standard_id"],
                    },
                )

            if "file:hashes.'SHA-256'" in observable_type:
                hashes["SHA-256"] = observable_value

            if "file:hashes.MD5" in observable_type:
                hashes["MD5"] = observable_value

            if "file:hashes.'SHA-1'" in observable_type:
                hashes["SHA-1"] = observable_value

            return stix2.File(
                hashes=hashes,
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
        elif observable_type == "file:name":
            return stix2.File(
                name=observable_name,
                hashes=full_observable_hashes,
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
        elif observable_type == "domain-name:value":
            return stix2.DomainName(
                value=observable_value,
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
        elif observable_type == "ipv4-addr:value":
            return stix2.IPv4Address(
                value=observable_value,
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
        elif observable_type == "ipv6-addr:value":
            return stix2.IPv6Address(
                value=observable_value,
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
        elif observable_type == "url:value":
            return stix2.URL(
                value=observable_value,
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
        else:
            return None

    def generate_stix_bundle(self, bundle_objects):
        if len(bundle_objects) > 0:
            stix_bundle = self.helper.stix2_create_bundle(bundle_objects)
            now = datetime.now(tz=timezone.utc)
            friendly_name = "HarfangLab run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            self.helper.send_stix2_bundle(stix_bundle, work_id=work_id)
            message = "Connector successfully run"
            self.helper.api.work.to_processed(work_id, message)

    def process_stix_relationship(
        self, stix_core_relationship_type, source_ref, target_ref, stix2_marking
    ):
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            object_marking_refs=[stix2_marking],
            created_by_ref=self.identity["standard_id"],
        )

    def alerts_in_case_incident(self, bundle_observables, threat_id):
        # Handle Alerts and relationship Case Incidents
        alerts_filtered_by_threat = self.get_alerts_filtered(1, int(threat_id))
        if int(alerts_filtered_by_threat["count"]) > 0:
            alerts_filtered_total_count = int(alerts_filtered_by_threat["count"])
            alerts_filtered_by_threat = self.get_alerts_filtered(
                alerts_filtered_total_count, threat_id
            )

            bundle_references = []
            filtered_alerts_in_threats_by_date = self.sort_object_unique(
                alerts_filtered_by_threat["results"], "@event_create_date"
            )

            for filtered_alert_in_threat in filtered_alerts_in_threats_by_date:
                new_alert_built = self.build_alert_object(filtered_alert_in_threat)

                if new_alert_built["alert_type"] == "ioc":
                    msg_parsed = self.msg_parser(new_alert_built)
                    if msg_parsed is None:
                        return self.helper.log_error(
                            "[ERROR] An error occurred while parsing msg."
                        )

                    for bundle_observable in bundle_observables:
                        if bundle_observable["type"] == "file":
                            if "SHA-256" in bundle_observable["hashes"]:
                                if (
                                    msg_parsed == bundle_observable["hashes"]["SHA-256"]
                                    or bundle_observable["hashes"]["SHA-256"]
                                    == new_alert_built["process"]["hashes"]["sha256"]
                                ):
                                    bundle_references.append(bundle_observable)

                            if "SHA-1" in bundle_observable["hashes"]:
                                if (
                                    msg_parsed == bundle_observable["hashes"]["SHA-1"]
                                    or bundle_observable["hashes"]["SHA-1"]
                                    == new_alert_built["process"]["hashes"]["sha1"]
                                ):
                                    bundle_references.append(bundle_observable)

                            if "MD5" in bundle_observable["hashes"]:
                                if (
                                    msg_parsed == bundle_observable["hashes"]["MD5"]
                                    or bundle_observable["hashes"]["MD5"]
                                    == new_alert_built["process"]["hashes"]["md5"]
                                ):
                                    bundle_references.append(bundle_observable)

                        elif bundle_observable["type"] == "directory":
                            if (
                                bundle_observable["path"]
                                == new_alert_built["process"]["current_directory"]
                            ):
                                bundle_observable["linked_to"] = new_alert_built[
                                    "process"
                                ]["hashes"]["sha256"]
                                bundle_references.append(bundle_observable)

                        else:
                            if "value" in bundle_observable:
                                if msg_parsed == bundle_observable["value"]:
                                    bundle_references.append(bundle_observable)
                            else:
                                continue

            return bundle_references

    @staticmethod
    def sort_object_unique(stix_objects, sort_by):
        list_stix_data_sorted = {}
        for stix_object in stix_objects:
            list_stix_data_sorted[stix_object[sort_by]] = stix_object
        return list(list_stix_data_sorted.values())

    @staticmethod
    def get_match(data, key, value):
        return next((x for x in data if x[key] == value), None)

    @staticmethod
    def stix_convert_type(attribute_type, value, alert=None):
        if attribute_type == "domain_name":
            new_stix_attribute = attribute_type.replace(
                "domain_name", "domain-name:value"
            )
        elif attribute_type == "filename":
            new_stix_attribute = attribute_type.replace("filename", "file:name")
        elif attribute_type == "filepath":
            # if value.upper().startswith('C:\\USERS'):
            new_stix_attribute = attribute_type.replace("filepath", "file:name")

        elif attribute_type in ["ip_src", "ip_dst", "ip_both"]:
            regex_ipv4 = r"(?:\d{1,3}\.){3}\d{1,3}"
            regex_ipv6 = r"(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-f]{1,4}"

            is_ipv4 = re.match(regex_ipv4, value)
            is_ipv6 = re.match(regex_ipv6, value)

            if is_ipv4:
                new_stix_attribute = (
                    attribute_type.replace("ip_both", "ipv4-addr:value")
                    .replace("ip_dst", "ipv4-addr:value")
                    .replace("ip_src", "ipv4-addr:value")
                )
            elif is_ipv6:
                new_stix_attribute = (
                    attribute_type.replace("ip_both", "ipv6-addr:value")
                    .replace("ip_dst", "ipv6-addr:value")
                    .replace("ip_src", "ipv6-addr:value")
                )
        elif attribute_type == "url":
            new_stix_attribute = attribute_type.replace("url", "url:value")
        elif attribute_type == "hash":
            regex_sha512 = r"[0-9a-fA-F]{128}"
            regex_sha256 = r"[0-9a-fA-F]{64}"
            regex_sha1 = r"[0-9a-fA-F]{40}"
            regex_md5 = r"[0-9a-fA-F]{32}"

            is_regex_sha512 = re.match(regex_sha512, value)
            is_regex_sha256 = re.match(regex_sha256, value)
            is_regex_sha1 = re.match(regex_sha1, value)
            is_regex_md5 = re.match(regex_md5, value)

            if is_regex_sha512:
                new_stix_attribute = attribute_type.replace(
                    "hash", "file:hashes.'SHA-512'"
                )
            elif is_regex_sha256:
                new_stix_attribute = attribute_type.replace(
                    "hash", "file:hashes.'SHA-256'"
                )
            elif is_regex_sha1:
                new_stix_attribute = attribute_type.replace(
                    "hash", "file:hashes.'SHA-1'"
                )
            elif is_regex_md5:
                new_stix_attribute = attribute_type.replace("hash", "file:hashes.MD5")
            else:
                new_stix_attribute = None

        return new_stix_attribute

    @staticmethod
    def build_alert_object(alert):
        new_alert = {
            "alert_id": alert["alert_unique_id"],
            "status": alert["status"],
            "msg": alert["msg"],
            "rule_name": alert["rule_name"],
            "alert_type": alert["alert_type"],
            "log_type": alert["log_type"],
            "level": alert["level"],
            "maturity": alert["maturity"],
            "process": {
                "username": alert["process"]["username"],
                "user_sid": alert["process"]["usersid"],
                "process_name": alert["process"]["process_name"],
                "hashes": alert["process"]["hashes"],
                "current_directory": alert["process"]["current_directory"],
            },
            "agent": {
                "hostname": alert["agent"]["hostname"],
                "agent_id": alert["agent"]["agentid"],
                "os_type": alert["agent"]["ostype"],
                "os_product_type": alert["agent"]["osproducttype"],
            },
            "url_id": alert["id"],
            "created_at": alert["@event_create_date"],
        }
        if "last_update" in alert:
            new_alert["updated_at"] = alert["last_update"]
        return new_alert

    @staticmethod
    def msg_parser(alert):
        msg = alert["msg"]
        match = re.search(r"=", msg)
        if match:
            msg_splited = msg.replace(" ", "").split("=")
        else:
            msg_splited = msg.replace(" ", "").split(":")

        if len(msg_splited) == 2:
            return msg_splited[1]
        else:
            return None

    def get_alerts_filtered(self, count=1, threat_id=None):
        if threat_id is not None:
            return self._query(
                "/alert/alert/Alert/"
                + f"?limit={count}"
                + f"&threat_key={threat_id}"
                + f"&status={self.import_security_events_filters_by_status}"
                + f"&alert_type={self.import_filters_by_alert_type}"
            )
        else:
            return self._query(
                "/alert/alert/Alert?maturity=stable"
                + f"&limit={count}"
                + f"&status={self.import_security_events_filters_by_status}"
                + f"&alert_type={self.import_filters_by_alert_type}"
            )

    def handle_marking(self):
        marking = self.check_and_return_marking_definition()

        # Convert Markings for Stix2
        if marking["definition"] == "TLP:CLEAR":
            return stix2.TLP_WHITE
        elif marking["definition"] == "TLP:GREEN":
            return stix2.TLP_GREEN
        elif marking["definition"] == "TLP:AMBER":
            return stix2.TLP_AMBER
        elif marking["definition"] == "TLP:RED":
            return stix2.TLP_RED
        else:
            # Default markings
            self.helper.log_error(
                "[ERROR] Marketing is either missing or not on the list. TLP:CLEAR is set."
            )
            return stix2.TLP_WHITE

    def check_and_return_marking_definition(self):
        marking_definition_default = "TLP:CLEAR"
        marking_definition_config = self.default_markings
        marking_definition_list = self.helper.api.marking_definition.list()

        for marking_definition in marking_definition_list:
            if marking_definition["definition"] == marking_definition_config:
                return marking_definition

        for marking_definition in marking_definition_list:
            if marking_definition["definition"] == marking_definition_default:
                return marking_definition

    def _query(self, uri):
        response = requests.get(
            self.api_url + uri, headers=self.headers, verify=self.ssl_verify
        )
        if response.status_code == 200:
            try:
                return response.json()
            except:
                return response.text
