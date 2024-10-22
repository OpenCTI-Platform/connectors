################################################
# HarfangLab Connector - Sightings             #
################################################

import re
import threading
import time
from datetime import datetime, timezone

import pytz
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
        harfanglab_default_score,
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
        self.default_score = harfanglab_default_score

        # Identity
        self.identity = self.helper.api.identity.create(
            type="System",
            name=self.helper.get_name(),
            description=f"System {self.helper.get_name()}",
        )

    def run(self):
        while True:
            try:
                # Get the current state and check if connector already runs
                now = datetime.now().astimezone(pytz.UTC)
                date_now_convert = now.strftime("%Y-%m-%dT%H:%M:%SZ")
                current_state = self.helper.get_state()

                if (
                    "recover_until" in current_state
                    and current_state["recover_until"] < date_now_convert
                ):
                    last_run = current_state["recover_until"]

                    msg = (
                        "[CONNECTOR] Connector last run: "
                        + current_state["recover_until"]
                    )
                    self.helper.log_info(msg)
                else:
                    last_run = None
                    msg = "[CONNECTOR] Connector has never run..."
                    self.helper.log_info(msg)

                if (
                    self.import_threats_as_case_incidents is False
                    and self.import_security_events_as_incidents is True
                ):
                    self.helper.log_info("[INCIDENTS] Starting alerts gatherer")
                    self.create_incident(last_run)
                    self.helper.log_info(
                        "[INCIDENTS] Incidents creations completed successfully"
                    )

                elif self.import_threats_as_case_incidents is True:
                    self.helper.log_info(
                        "[INCIDENTS/CASE-INCIDENTS] Starting alerts gatherer"
                    )
                    self.create_incident(last_run)
                    self.helper.log_info(
                        "[INCIDENTS] Incidents creations completed successfully"
                    )
                    self.create_case_incident(last_run)
                    self.helper.log_info(
                        "[CASE-INCIDENTS] Case-Incidents creations completed successfully"
                    )

                time.sleep(60)

            except Exception as e:
                error_msg = f"[CONNECTOR] Error while processing data: {str(e)}"
                self.helper.log_error(error_msg)

    def filtered_by_date(self, filtered_data, key_date, last_run):
        last_date_data = filtered_data[0].get(key_date, "")

        if last_date_data:
            if last_run is None:
                now = datetime.now().astimezone(pytz.UTC)
                date_convert = datetime.strftime(now, "%Y-%m-%dT%H:%M:%SZ")
                self.helper.set_state({"recover_until": date_convert})
                return filtered_data
            else:
                if key_date == "@event_create_date":
                    # Format date Alert
                    last_date_data_convert = datetime.strptime(
                        last_date_data, "%Y-%m-%dT%H:%M:%S.%fZ"
                    )
                else:
                    # Format date Threat
                    last_date_data_convert = datetime.strptime(
                        last_date_data, "%Y-%m-%dT%H:%M:%SZ"
                    )

                last_run_convert = datetime.strptime(last_run, "%Y-%m-%dT%H:%M:%SZ")

                if last_date_data_convert >= last_run_convert:
                    now = datetime.now().astimezone(pytz.UTC)
                    date_convert = datetime.strftime(now, "%Y-%m-%dT%H:%M:%SZ")
                    self.helper.set_state({"recover_until": date_convert})
                    return [
                        data for data in filtered_data if data[key_date] >= last_run
                    ]

    def create_incident(self, last_run=None):
        alert_filtered = self.get_alerts_filtered()
        alerts_filtered_total_count = int(alert_filtered["count"])

        if alerts_filtered_total_count == 0:
            return self.helper.log_info(
                "[INCIDENTS] No security events have been detected at HarfangLab"
            )

        alerts_filtered = self.get_alerts_filtered(alerts_filtered_total_count)
        alerts_filtered_by_date = self.filtered_by_date(
            alerts_filtered["results"], "@event_create_date", last_run
        )

        if alerts_filtered_by_date is None:
            return self.helper.log_info(
                "[INCIDENTS] No new security events have been detection"
            )

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
        all_attacks_pattern = []
        all_relationships = []

        for alert in alerts_filtered_by_date:
            new_alert_built = self.build_alert_object(alert)

            if new_alert_built["alert_type"] == "ioc":
                msg_parsed = self.msg_parser(new_alert_built)
                if msg_parsed is None:
                    self.helper.log_error(
                        "[ERROR] An error occurred while parsing msg."
                    )
                    continue

                indicators_ioc_info = self._query(
                    f"/threat_intelligence/IOCRule/?value={msg_parsed}"
                )

                # If the indicator does not exist or no longer exists at HarfangLab
                if not indicators_ioc_info["results"]:
                    self.helper.log_error(
                        f"[ERROR] The IOC rule '{msg_parsed}' that was triggered does not exist or no longer exists at HarfangLab."
                    )
                    continue
                else:
                    indicator_matching = self.get_match(
                        indicators_ioc_info["results"], "value", msg_parsed
                    )

                    # Generate incident
                    build_observable_hashes = {}
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
                                        build_observable_hashes["name"] = (
                                            search_observable["name"]
                                        )
                                    for observable_hash in search_observable["hashes"]:
                                        if (
                                            "SHA-256" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes["SHA-256"] = (
                                                observable_hash["hash"]
                                            )
                                        if (
                                            "SHA-1" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes["SHA-1"] = (
                                                observable_hash["hash"]
                                            )
                                        if (
                                            "MD5" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes["MD5"] = (
                                                observable_hash["hash"]
                                            )

                        elif search_observables and not observable_matching:
                            for search_observable in search_observables:
                                if "hashes" in search_observable:
                                    if "name" in search_observable:
                                        build_observable_hashes["name"] = (
                                            search_observable["name"]
                                        )
                                    for observable_hash in search_observable["hashes"]:
                                        if (
                                            "SHA-256" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes["SHA-256"] = (
                                                observable_hash["hash"]
                                            )
                                        if (
                                            "SHA-1" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes["SHA-1"] = (
                                                observable_hash["hash"]
                                            )
                                        if (
                                            "MD5" in observable_hash["algorithm"]
                                            and observable_hash["algorithm"] != ""
                                        ):
                                            build_observable_hashes["MD5"] = (
                                                observable_hash["hash"]
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

                    alert_create_date = new_alert_built["created_at"]
                    if "updated_at" in new_alert_built:
                        alert_update_date = new_alert_built["updated_at"]
                    else:
                        alert_update_date = new_alert_built["created_at"]

                    stix_incident = stix2.Incident(
                        id=Incident.generate_id(incident_name, alert_create_date),
                        created=alert_create_date,
                        name=incident_name,
                        description=f"{new_alert_built['msg']}",
                        object_marking_refs=[convert_marking_for_stix2],
                        created_by_ref=self.identity["standard_id"],
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
                            for key, value in build_observable_hashes.items():
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
                                "x_opencti_score": self.default_score,
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
                        all_observable_objects.append(
                            {
                                "incident_id": stix_incident["id"],
                                "stix_observable": stix_observable,
                            }
                        )

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
                    all_hostnames_objects.append(
                        {
                            "incident_id": stix_incident["id"],
                            "stix_hostname": stix_hostname,
                        }
                    )

                    # Create Observable User Account
                    stix_user = stix2.UserAccount(
                        account_login=new_alert_built["process"]["username"],
                        object_marking_refs=[convert_marking_for_stix2],
                        custom_properties={
                            "created_by_ref": self.identity["standard_id"],
                        },
                    )
                    all_users_objects.append(
                        {
                            "incident_id": stix_incident["id"],
                            "stix_user": stix_user,
                        }
                    )

            if new_alert_built["alert_type"] == "sigma":
                indicators_sigma_info = self._query(
                    f"/threat_intelligence/SigmaRule/?search={new_alert_built['rule_name']}"
                )

                # If the indicator does not exist or no longer exists at HarfangLab
                if not indicators_sigma_info["results"]:
                    self.helper.log_error(
                        f"[ERROR] The Sigma rule '{new_alert_built['rule_name']}' that was triggered does not exist or no longer exists at HarfangLab."
                    )
                    continue
                else:
                    self.helper.log_info("[CREATE] Creating Sigma indicator")
                    bundle = self.process_create_bundle(
                        indicators_sigma_info,
                        new_alert_built,
                        convert_marking_for_stix2,
                        "sigma",
                    )
                    if not bundle:
                        continue
                    else:
                        for key, value in bundle.items():
                            if key == "all_incidents_objects":
                                all_incidents_objects.append(value)
                            elif key == "all_indicators_objects":
                                all_indicators_objects.append(value)
                            elif key == "all_sightings_objects":
                                all_sightings_objects.append(value)
                            elif key == "all_hostnames_objects":
                                all_hostnames_objects.append(value)
                            elif key == "all_users_objects":
                                all_users_objects.append(value)
                            elif key == "all_observable_objects":
                                all_observable_objects.append(value)
                            elif key == "all_relationships":
                                for relationship in value:
                                    all_relationships.append(relationship)
                            elif key == "all_observables_directories":
                                all_observables_directories.append(value)
                            elif key == "all_attacks_pattern":
                                for attack_pattern in value:
                                    all_attacks_pattern.append(attack_pattern)
                            else:
                                continue

            if new_alert_built["alert_type"] == "yara":
                msg_splited = new_alert_built["rule_name"].replace(" ", "").split(":")
                if len(msg_splited) == 2:
                    indicator_name = msg_splited[1]
                else:
                    self.helper.log_error(
                        "[ERROR] An error occurred while parsing msg."
                    )
                    continue

                indicators_yara_info = self._query(
                    f"/threat_intelligence/YaraFile/?search={indicator_name}"
                )

                # If the indicator does not exist or no longer exists at HarfangLab
                if not indicators_yara_info["results"]:
                    self.helper.log_error(
                        f"[ERROR] The Yara rule '{indicator_name}' that was triggered does not exist or no longer exists at HarfangLab."
                    )
                    continue
                else:
                    self.helper.log_info("[CREATE] Creating Yara indicator")
                    bundle = self.process_create_bundle(
                        indicators_yara_info,
                        new_alert_built,
                        convert_marking_for_stix2,
                        "yara",
                        indicator_name,
                    )
                    if not bundle:
                        continue
                    else:
                        for key, value in bundle.items():
                            if key == "all_incidents_objects":
                                all_incidents_objects.append(value)
                            elif key == "all_indicators_objects":
                                all_indicators_objects.append(value)
                            elif key == "all_sightings_objects":
                                all_sightings_objects.append(value)
                            elif key == "all_hostnames_objects":
                                all_hostnames_objects.append(value)
                            elif key == "all_users_objects":
                                all_users_objects.append(value)
                            elif key == "all_observable_objects":
                                all_observable_objects.append(value)
                            elif key == "bundle_objects":
                                for relationship in value:
                                    bundle_objects.append(relationship)
                            elif key == "all_observables_directories":
                                all_observables_directories.append(value)
                            elif key == "all_attacks_pattern":
                                for attack_pattern in value:
                                    all_attacks_pattern.append(attack_pattern)
                            else:
                                continue

        list_of_directories = all_observables_directories.copy()
        for observable_directory in list_of_directories:
            bundle_objects.append(observable_directory["stix_directory"])

        list_of_attacks_pattern = all_attacks_pattern.copy()
        for attack_pattern in list_of_attacks_pattern:
            bundle_objects.append(attack_pattern["stix_attack_pattern"])

        stix_observables = []
        for observable in all_observable_objects:
            stix_observables.append(observable["stix_observable"])

        list_of_observables_unique = self.sort_object_unique(stix_observables, "id")
        for observable in list_of_observables_unique:
            bundle_objects.append(observable)

        list_of_indicators_unique = all_indicators_objects.copy()
        for indicator in list_of_indicators_unique:
            bundle_objects.append(indicator)

        for indicator_unique in list_of_indicators_unique:
            for relationship in all_relationships:
                if indicator_unique["id"] == relationship["source_ref"]:
                    bundle_objects.append(relationship)

                elif indicator_unique["id"] == relationship["target_ref"]:
                    bundle_objects.append(relationship)

            for observable_unique in list_of_observables_unique:
                list_of_id = []
                for relationship in all_relationships:
                    if observable_unique["id"] == relationship["source_ref"]:
                        list_of_id.append(relationship["target_ref"])

                    elif indicator_unique["id"] == relationship["target_ref"]:
                        bundle_objects.append(relationship)
                        list_of_id.append(relationship["source_ref"])

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
                for attack_pattern_object in list_of_attacks_pattern:
                    if global_item["id"] == attack_pattern_object["incident_id"]:
                        # Generate relationship : incident -> type "uses" -> attack pattern
                        stix_relation_new_indicator = self.process_stix_relationship(
                            "uses",
                            global_item["id"],
                            attack_pattern_object["stix_attack_pattern"]["id"],
                            convert_marking_for_stix2,
                        )
                        bundle_objects.append(stix_relation_new_indicator)

                list_of_id_linked_to_incident = []

                for relationship in all_relationships:
                    if global_item["id"] == relationship["source_ref"]:
                        bundle_objects.append(relationship)
                        list_of_id_linked_to_incident.append(relationship["target_ref"])

                    elif global_item["id"] == relationship["target_ref"]:
                        bundle_objects.append(relationship)
                        list_of_id_linked_to_incident.append(relationship["source_ref"])

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

                for observable in all_observable_objects:
                    if observable["incident_id"] == global_item["id"]:
                        bundle_objects.append(observable["stix_observable"])

                        # Generate relationship : observable -> type "related-to" -> incident
                        stix_relation_new_observable = self.process_stix_relationship(
                            "related-to",
                            observable["stix_observable"]["id"],
                            global_item["id"],
                            convert_marking_for_stix2,
                        )
                        bundle_objects.append(stix_relation_new_observable)

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

                for hostname in all_hostnames_objects:
                    if hostname["incident_id"] == global_item["id"]:
                        bundle_objects.append(hostname["stix_hostname"])

                        # Generate relationship : Hostname -> type "related-to" -> incident
                        stix_relation_hostname = self.process_stix_relationship(
                            "related-to",
                            hostname["stix_hostname"]["id"],
                            global_item["id"],
                            convert_marking_for_stix2,
                        )
                        bundle_objects.append(stix_relation_hostname)

                for user in all_users_objects:
                    if user["incident_id"] == global_item["id"]:
                        bundle_objects.append(user["stix_user"])

                        # Generate relationship : Hostname -> type "related-to" -> incident
                        stix_relation_user = self.process_stix_relationship(
                            "related-to",
                            user["stix_user"]["id"],
                            global_item["id"],
                            convert_marking_for_stix2,
                        )
                        bundle_objects.append(stix_relation_user)

        global_sightings = self.handling_of_sightings_and_external_references(
            all_sightings_objects
        )
        for global_sighting in global_sightings:
            bundle_objects.append(global_sighting)

        self.generate_stix_bundle(bundle_objects)
        self.list_info = {
            "bundle_objects": bundle_objects,
            "list_of_sightings": all_sightings_objects,
            "list_of_incidents": all_incidents_objects,
            "list_of_indicators": list_of_indicators_unique,
            "list_of_observables": all_observable_objects,
            "list_of_directories": list_of_directories,
            "list_of_attacks_pattern": list_of_attacks_pattern,
        }
        return

    def create_case_incident(self, last_run):
        list_info = self.list_info
        threats = self._query("/alert/alert/Threat")
        threats_filtered_by_date = self.filtered_by_date(
            threats["results"], "last_seen", last_run
        )

        if threats_filtered_by_date is None:
            return self.helper.log_info(
                "[CASE-INCIDENTS] No new threats or updates detected"
            )

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
        bundle_attacks_pattern = []

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
            elif bundle["type"] == "attack-pattern":
                bundle_attacks_pattern.append(bundle)
            else:
                bundle_observables.append(bundle)

        for threat in threats_filtered_by_date:
            case_incident_date = parse(threat["first_seen"]).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

            list_of_references_alerts = self.alerts_in_case_incident(
                bundle_relationships,
                bundle_observables,
                bundle_indicators,
                threat["id"],
            )

            if list_of_references_alerts is None or not list_of_references_alerts:
                continue
            else:
                merge_all_references = []

                # Add observables linked to the threat (case incident) in the merge_all_references
                list_of_references_alerts_unique = self.sort_object_unique(
                    list_of_references_alerts, "id"
                )
                for reference in list_of_references_alerts_unique:
                    merge_all_references.append(reference)

                    # Add incidents linked to the threat (case incident) in the merge_all_references
                    for bundle_incident in bundle_incidents:
                        incident_hostname = bundle_incident["name"].split(" on ", 1)

                        # Add observables linked to the threat (case incident) in the merge_all_references
                        if reference["type"] == "file":
                            if "SHA-256" in reference["hashes"]:
                                if bundle_incident["name"].startswith(
                                    reference["hashes"]["SHA-256"]
                                ):
                                    merge_all_references.append(bundle_incident)

                            if "SHA-1" in reference["hashes"]:
                                if bundle_incident["name"].startswith(
                                    reference["hashes"]["SHA-1"]
                                ):
                                    merge_all_references.append(bundle_incident)

                            if "MD5" in reference["hashes"]:
                                if bundle_incident["name"].startswith(
                                    reference["hashes"]["MD5"]
                                ):
                                    merge_all_references.append(bundle_incident)

                            if "name" in reference:
                                name_splited = reference["name"].split(".")
                                if bundle_incident["name"].startswith(name_splited[0]):
                                    merge_all_references.append(bundle_incident)

                            if "linked_to" in reference:
                                if (
                                    bundle_incident["description"]
                                    == reference["linked_to"]
                                ):
                                    if reference["hostname"] == incident_hostname[1]:
                                        merge_all_references.append(bundle_incident)

                        elif reference["type"] == "directory":
                            if bundle_incident["name"].startswith(reference["hash256"]):
                                merge_all_references.append(bundle_incident)

                        elif reference["type"] == "indicator":
                            if bundle_incident["name"].startswith(reference["name"]):
                                merge_all_references.append(bundle_incident)

                        elif bundle_incident["name"].startswith(reference["value"]):
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

                # Add relationships (incident, attack pattern, observable) linked to the threat (case incident) in the merge_all_references
                for reference in merge_all_references:
                    if reference["type"] == "incident":
                        for bundle_relationship in bundle_relationships:
                            if reference["id"] == bundle_relationship["target_ref"]:
                                merge_all_references.append(bundle_relationship)

                            if reference["id"] == bundle_relationship["source_ref"]:
                                merge_all_references.append(bundle_relationship)

                        for global_info in list_info["list_of_attacks_pattern"]:
                            if global_info["incident_id"] == reference["id"]:
                                merge_all_references.append(
                                    global_info["stix_attack_pattern"]
                                )

                    else:
                        continue

                relationship_sorted = self.sort_object_unique(
                    bundle_relationships, "id"
                )
                for bundle_relationship in relationship_sorted:
                    merge_all_references.append(bundle_relationship)

                stix_case_incident = CustomObjectCaseIncident(
                    id=CaseIncident.generate_id(threat["slug"], case_incident_date),
                    name=f"{threat['slug']} on {threat['top_agents'][0]['agent_hostname']}",
                    # description=description,
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

    def handling_of_sightings_and_external_references(self, all_sightings_objects):
        new_object = {}
        for sighting_sorted_by_ref in all_sightings_objects:
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
                    self.identity["standard_id"],
                    alert_date,
                    alert_date,
                ),
                first_seen=sighting["first_seen"],
                last_seen=sighting["last_seen"],
                count=int(len(external_references)),
                sighting_of_ref=sighting["sighting_of_ref"],
                where_sighted_refs=[self.identity["standard_id"]],
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
                self.identity["standard_id"],
                alert_date,
                alert_date,
            ),
            first_seen=new_alert_built["created_at"],
            last_seen=new_alert_built["updated_at"],
            sighting_of_ref=indicator,
            where_sighted_refs=[self.identity["standard_id"]],
            count=1,
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
                if (
                    "SHA-256" in build_observable_hashes
                    and build_observable_hashes["SHA-256"] is not None
                ):
                    hashes["SHA-256"] = build_observable_hashes["SHA-256"]

                if (
                    "SHA-1" in build_observable_hashes
                    and build_observable_hashes["SHA-1"] is not None
                ):
                    hashes["SHA-1"] = build_observable_hashes["SHA-1"]

                if (
                    "MD5" in build_observable_hashes
                    and build_observable_hashes["MD5"] is not None
                ):
                    hashes["MD5"] = build_observable_hashes["MD5"]

                return stix2.File(
                    name=build_observable_hashes["name"],
                    hashes=hashes,
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

    def alerts_in_case_incident(
        self, list_of_relationships, list_of_observables, bundle_indicators, threat_id
    ):
        bundle_observables = self.sort_object_unique(list_of_observables, "id")

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

                    for bundle_indicator in bundle_indicators:
                        if bundle_indicator["pattern_type"] == "stix":
                            if bundle_indicator["name"] == msg_parsed:
                                bundle_references.append(bundle_indicator)

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
                                    "rule_name"
                                ]
                                bundle_observable["hash256"] = new_alert_built[
                                    "process"
                                ]["hashes"]["sha256"]
                                bundle_references.append(bundle_observable)

                        else:
                            if "value" in bundle_observable:
                                if msg_parsed == bundle_observable["value"]:
                                    bundle_references.append(bundle_observable)
                            else:
                                continue

                elif (
                    new_alert_built["alert_type"] == "sigma"
                    or new_alert_built["alert_type"] == "yara"
                ):
                    # Add indicator linked to the threat (case incident) in the merge_all_references
                    if new_alert_built["alert_type"] == "sigma":
                        for bundle_indicator in bundle_indicators:
                            if bundle_indicator["pattern_type"] == "sigma":
                                if bundle_indicator["pattern"].startswith(
                                    "title: " + new_alert_built["rule_name"]
                                ):
                                    bundle_references.append(bundle_indicator)
                    else:
                        for bundle_indicator in bundle_indicators:
                            if bundle_indicator["pattern_type"] == "yara":
                                if new_alert_built["process"][
                                    "process_name"
                                ].startswith(bundle_indicator["name"]):
                                    bundle_references.append(bundle_indicator)

                    # check observable exist in alert
                    for bundle_observable in bundle_observables:
                        if bundle_observable["type"] == "file":
                            if (
                                "SHA-256" in bundle_observable["hashes"]
                                and bundle_observable["hashes"]["SHA-256"]
                            ):
                                if (
                                    bundle_observable["hashes"]["SHA-256"]
                                    == new_alert_built["process"]["hashes"]["sha256"]
                                ):
                                    bundle_observable["linked_to"] = new_alert_built[
                                        "msg"
                                    ]
                                    bundle_observable["hostname"] = new_alert_built[
                                        "agent"
                                    ]["hostname"]
                                    bundle_references.append(bundle_observable)

                            elif (
                                "SHA-1" in bundle_observable["hashes"]
                                and bundle_observable["hashes"]["SHA-1"]
                            ):
                                if (
                                    bundle_observable["hashes"]["SHA-1"]
                                    == new_alert_built["process"]["hashes"]["sha1"]
                                ):
                                    bundle_observable["linked_to"] = new_alert_built[
                                        "msg"
                                    ]
                                    bundle_observable["hostname"] = new_alert_built[
                                        "agent"
                                    ]["hostname"]
                                    bundle_references.append(bundle_observable)

                            elif (
                                "MD5" in bundle_observable["hashes"]
                                and bundle_observable["hashes"]["MD5"]
                            ):
                                if (
                                    bundle_observable["hashes"]["MD5"]
                                    == new_alert_built["process"]["hashes"]["md5"]
                                ):
                                    bundle_observable["linked_to"] = new_alert_built[
                                        "msg"
                                    ]
                                    bundle_observable["hostname"] = new_alert_built[
                                        "agent"
                                    ]["hostname"]
                                    bundle_references.append(bundle_observable)

                            elif (
                                "name" in bundle_observable
                                and bundle_observable["name"]
                            ):
                                if (
                                    bundle_observable["name"]
                                    == new_alert_built["process"]["process_name"]
                                ):
                                    bundle_observable["linked_to"] = new_alert_built[
                                        "rule_name"
                                    ]
                                    bundle_observable["hostname"] = new_alert_built[
                                        "agent"
                                    ]["hostname"]
                                    bundle_references.append(bundle_observable)

                        elif bundle_observable["type"] == "directory":
                            if (
                                bundle_observable["path"]
                                == new_alert_built["process"]["current_directory"]
                            ):
                                bundle_observable["linked_to"] = new_alert_built[
                                    "rule_name"
                                ]
                                bundle_observable["hash256"] = new_alert_built[
                                    "process"
                                ]["hashes"]["sha256"]
                                bundle_references.append(bundle_observable)

            return bundle_references

    def process_create_bundle(
        self,
        indicators_info,
        new_alert_built,
        marking,
        pattern_type,
        indicator_name=None,
    ):
        global_bundle = {}

        if pattern_type == "yara":
            indicator_matching = {}

            for indicator in indicators_info["results"]:
                for indicator_rule_name in indicator["rule_names"]:
                    if indicator_rule_name == indicator_name:
                        indicator_matching = indicator

        elif pattern_type == "sigma":
            indicator_matching = self.get_match(
                indicators_info["results"], "rule_name", new_alert_built["rule_name"]
            )

        elif pattern_type == "ioc":
            return

        else:
            indicator_matching = None

        if indicator_matching is not None:
            incident_name = (
                indicator_matching["name"]
                + " on "
                + new_alert_built["agent"]["hostname"]
            )
            indicator_name = indicator_matching["name"]

            alert_create_date = new_alert_built["created_at"]
            if "updated_at" in new_alert_built:
                alert_update_date = new_alert_built["updated_at"]
            else:
                alert_update_date = new_alert_built["created_at"]

            # Generate new incident
            stix_incident = stix2.Incident(
                id=Incident.generate_id(incident_name, alert_create_date),
                created=alert_create_date,
                name=incident_name,
                description=f"{new_alert_built['msg']}",
                object_marking_refs=[marking],
                created_by_ref=self.identity["standard_id"],
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
            global_bundle["all_incidents_objects"] = stix_incident

            # Generate new indicator
            stix_indicator = stix2.Indicator(
                id=Indicator.generate_id(indicator_name),
                created_by_ref=self.identity["standard_id"],
                created=indicator_matching["creation_date"],
                modified=indicator_matching["last_update"],
                name=indicator_name,
                description=(
                    indicator_matching["description"]
                    if "description" in indicator_matching
                    else ""
                ),
                pattern=indicator_matching["content"],
                object_marking_refs=[marking],
                custom_properties={
                    "pattern_type": pattern_type,
                    "x_opencti_score": self.default_score,
                    "detection": True,
                },
            )
            global_bundle["all_indicators_objects"] = stix_indicator

            # Generate sighting : indicator -> type "sigthed in/at" -> system
            stix_sighting = self.process_create_sighting_relationship(
                new_alert_built,
                stix_indicator["id"],
                marking,
            )
            global_bundle["all_sightings_objects"] = stix_sighting

            # Create Observable Hostname
            stix_hostname = CustomObservableHostname(
                value=new_alert_built["agent"]["hostname"],
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
            global_bundle["all_hostnames_objects"] = {
                "incident_id": stix_incident["id"],
                "stix_hostname": stix_hostname,
            }

            # Create Observable User Account
            stix_user = stix2.UserAccount(
                account_login=new_alert_built["process"]["username"],
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
            global_bundle["all_users_objects"] = {
                "incident_id": stix_incident["id"],
                "stix_user": stix_user,
            }

            # Create observable File
            observable_name = new_alert_built["process"]["process_name"]
            stix_observable = stix2.File(
                name=observable_name,
                hashes={
                    "SHA-256": new_alert_built["process"]["hashes"]["sha256"],
                    "SHA-1": new_alert_built["process"]["hashes"]["sha1"],
                    "MD5": new_alert_built["process"]["hashes"]["md5"],
                },
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
            global_bundle["all_observable_objects"] = {
                "incident_id": stix_incident["id"],
                "stix_observable": stix_observable,
            }

            # Generate relationship : indicator -> type "based-on" -> observable
            stix_relation_new_indicator = self.process_stix_relationship(
                "based-on",
                stix_indicator["id"],
                stix_observable["id"],
                marking,
            )
            global_bundle["all_relationships"] = [stix_relation_new_indicator]

            # Generate relationship : observable -> type "related-to" -> incident
            stix_relation_new_observable = self.process_stix_relationship(
                "related-to",
                stix_observable["id"],
                stix_incident["id"],
                marking,
            )
            global_bundle["all_relationships"].append(stix_relation_new_observable)

            # Create observable directory
            observable_directory = new_alert_built["process"]["current_directory"]

            stix_observable_directory = stix2.Directory(
                path=observable_directory,
                object_marking_refs=[marking],
                custom_properties={
                    "created_by_ref": self.identity["standard_id"],
                },
            )
            global_bundle["all_observables_directories"] = {
                "incident_id": stix_incident["id"],
                "stix_directory": stix_observable_directory,
            }

            first_iteration = True
            for technique in indicator_matching["rule_technique_tags"]:
                # regex for tXXXX.XXX
                technique_number_complex = re.findall(r"t\d+\.\d+", technique)
                # regex for tXXXX
                technique_number_simple = re.findall(r"t\d+", technique)

                if technique_number_complex:
                    technique_matched = technique_number_complex[0].upper()
                elif technique_number_simple:
                    technique_matched = technique_number_simple[0].upper()
                else:
                    continue

                stix_attack_pattern = stix2.AttackPattern(
                    id=AttackPattern.generate_id(technique_matched, technique_matched),
                    name=technique_matched,
                    allow_custom=True,
                    custom_properties={"x_mitre_id": technique_matched},
                )

                if first_iteration is True:
                    global_bundle["all_attacks_pattern"] = [
                        {
                            "incident_id": stix_incident["id"],
                            "stix_attack_pattern": stix_attack_pattern,
                        }
                    ]
                    first_iteration = False
                else:
                    global_bundle["all_attacks_pattern"].append(
                        {
                            "incident_id": stix_incident["id"],
                            "stix_attack_pattern": stix_attack_pattern,
                        }
                    )

                # Generate relationship : incident -> type "use" -> attack_pattern
                stix_relation_attack_pattern = self.process_stix_relationship(
                    "uses",
                    stix_incident["id"],
                    stix_attack_pattern["id"],
                    marking,
                )
                global_bundle["all_relationships"].append(stix_relation_attack_pattern)

            return global_bundle
        else:
            return

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
