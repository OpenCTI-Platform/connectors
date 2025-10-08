import base64
import json
import os
import sys
import time
import traceback
import uuid
from datetime import datetime

import requests
import stix2
import yaml
from constants import DEFAULT_DATETIME, DEFAULT_UTC_DATETIME, PAP_MAPPINGS, TLP_MAPPINGS
from dateutil.parser import parse
from hive_observable_transform import (
    HiveObservableTransform,
    UnsupportedIndicatorTypeError,
)
from pycti import (
    CaseIncident,
    CustomObjectCaseIncident,
    CustomObjectTask,
    Incident,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    StixSightingRelationship,
    Task,
    get_config_variable,
)
from thehive4py import TheHiveApi
from thehive4py.query import Gt
from thehive4py.query.page import Paginate
from thehive4py.query.sort import Asc
from thehive4py.types.alert import OutputAlert
from thehive4py.types.case import OutputCase

from utils import format_datetime  # isort: skip


class TheHive:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.thehive_url = get_config_variable(
            "THEHIVE_URL", ["thehive", "url"], config
        )
        self.thehive_api_key = get_config_variable(
            "THEHIVE_API_KEY", ["thehive", "api_key"], config
        )
        self.thehive_check_ssl = get_config_variable(
            "THEHIVE_CHECK_SSL", ["thehive", "check_ssl"], config, False, True
        )
        self.thehive_organization_name = get_config_variable(
            "THEHIVE_ORGANIZATION_NAME", ["thehive", "organization_name"], config
        )
        self.thehive_import_from_date = get_config_variable(
            "THEHIVE_IMPORT_FROM_DATE",
            ["thehive", "import_from_date"],
            config,
            False,
            format_datetime(time.time(), DEFAULT_DATETIME),
        )
        self.thehive_import_from_date = parse(self.thehive_import_from_date).timestamp()
        self.thehive_import_only_tlp = get_config_variable(
            "THEHIVE_IMPORT_ONLY_TLP",
            ["thehive", "import_only_tlp"],
            config,
            False,
            "0,1,2,3,4",
        ).split(",")
        self.thehive_import_alerts = get_config_variable(
            "THEHIVE_IMPORT_ALERTS", ["thehive", "import_alerts"], config, False, True
        )
        self.thehive_severity_mapping = get_config_variable(
            "THEHIVE_SEVERITY_MAPPING",
            ["thehive", "severity_mapping"],
            config,
            False,
            "1:01 - low,2:02 - medium,3:03 - high,4:04 - critical",
        ).split(",")
        self.thehive_case_status_mapping = get_config_variable(
            "THEHIVE_CASE_STATUS_MAPPING",
            ["thehive", "case_status_mapping"],
            config,
            False,
            "",
        ).split(",")
        self.thehive_task_status_mapping = get_config_variable(
            "THEHIVE_TASK_STATUS_MAPPING",
            ["thehive", "case_task_mapping"],
            config,
            False,
            "",
        ).split(",")
        self.thehive_alert_status_mapping = get_config_variable(
            "THEHIVE_ALERT_STATUS_MAPPING",
            ["thehive", "case_alert_mapping"],
            config,
            False,
            "",
        ).split(",")
        self.thehive_user_mapping = get_config_variable(
            "THEHIVE_USER_MAPPING", ["thehive", "user_mapping"], config, False, ""
        ).split(",")
        self.thehive_interval = get_config_variable(
            "THEHIVE_INTERVAL", ["thehive", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name=self.thehive_organization_name,
            description=self.thehive_organization_name,
        )
        self.severity_mapping = {}
        for mapping in self.thehive_severity_mapping:
            self.severity_mapping[int(mapping.split(":")[0])] = mapping.split(":")[1]

        self.thehive_api = TheHiveApi(
            self.thehive_url, self.thehive_api_key, verify=self.thehive_check_ssl
        )

    def construct_query(self, type, last_date):
        """Construct query for alert or cases based on the last_date."""
        self.helper.log_info(
            f"Constructing query with last date: {format_datetime(last_date, DEFAULT_UTC_DATETIME)}"
        )
        if type == "case":
            return Gt("_updatedAt", int(last_date * 1000)) | Gt(
                "_createdAt", int(last_date * 1000)
            )
        elif type == "alert":
            return Gt("_updatedAt", int(last_date * 1000)) | Gt(
                "_createdAt", int(last_date * 1000)
            )
        else:
            raise ValueError(f"Unsupported type in construct_query: {type}")

    def convert_observable(self, observable, markings):
        """Converts the Hive Observable to a STIX observable."""
        stix_observable = None
        try:
            create_by_ref = self.identity.get("standard_id")
            u_observable = HiveObservableTransform(
                observable=observable,
                markings=markings,
                created_by_ref=create_by_ref,
            )
            stix_observable = u_observable.stix_observable
            self.helper.log_debug(
                f"Observable data_type ({u_observable.data_type}), stix observable: {u_observable.stix_observable}."
            )
        except UnsupportedIndicatorTypeError:
            self.helper.log_warning(f"Observable not supported: {observable}.")
        return stix_observable

    def create_stix_alert_incident(self, alert, markings, created, modified):
        """Function to create STIX incident from alert."""
        return stix2.Incident(
            id=Incident.generate_id(alert.get("title", ""), created),
            name=alert.get("title", ""),
            description=alert.get("description", ""),
            created=created,
            modified=modified,
            first_seen=created,
            last_seen=modified,
            object_marking_refs=markings,
            labels=alert.get("tags", []),
            created_by_ref=self.identity.get("standard_id", ""),
            allow_custom=True,
            custom_properties={
                "source": alert.get("source", ""),
                "severity": self.severity_mapping.get(alert.get("severity", ""), ""),
                "incident_type": "alert",
            },
        )

    def generate_alert_bundle(self, alert):
        """Generate a STIX bundle from a given alert."""

        # Initial logging
        self.helper.log_info(f"Starting import for alert '{alert.get('title')}'")
        bundle_objects = []
        try:
            markings = self.process_markings(alert)
            bundle_objects.extend(markings)
        except Exception as e:
            self.helper.log_error(f"Error processing markings: {str(e)}")
        created_epoch = alert.get("_createdAt", 0) / 1000
        created = format_datetime(created_epoch, DEFAULT_UTC_DATETIME)
        modified = format_datetime(
            self.get_updated_date(item=alert, last_date=created_epoch),
            DEFAULT_UTC_DATETIME,
        )
        stix_incident = self.create_stix_alert_incident(
            alert, markings, created, modified
        )
        bundle_objects.append(stix_incident)
        for observable in alert.get("artifacts", []):
            stix_observable, stix_relation = self.process_observables_and_relations(
                observable, markings, stix_incident
            )
            if stix_observable:
                bundle_objects.append(stix_observable)
                bundle_objects.append(stix_relation)
        try:
            bundle = self.helper.stix2_create_bundle(bundle_objects)
            self.helper.log_info(f"Completed import for alert '{alert.get('title')}'")
            return bundle
        except Exception as e:
            self.helper.log_error(
                f"Error serializing STIX bundle for 'alert': {str(e)}"
            )
            return {}

    def generate_case_bundle(self, case):
        """Generates a STIX bundle from a TheHive case, with attachments."""
        self.helper.log_info(
            f"Starting generation of STIX bundle for case: {case.get('title')}"
        )
        bundle_objects = []

        try:
            markings = self.process_markings(case)
            bundle_objects.extend(markings)
        except Exception as e:
            self.helper.log_error(f"Error processing markings: {str(e)}")

        processed_observables, case_object_refs = self.process_observables(
            case, markings
        )

        bundle_objects.extend(processed_observables)

        # Create a temporary dummy_case to get a valid STIX ID for attachments
        # Temporary creation of a STIX object to retrieve its ID
        dummy_case = CustomObjectCaseIncident(
            id=CaseIncident.generate_id(
                case.get("title"),
                format_datetime(
                    int(case.get("_createdAt")) / 1000, DEFAULT_UTC_DATETIME
                ),
            ),
            name=case.get("title"),
            created=format_datetime(
                int(case.get("_createdAt")) / 1000, DEFAULT_UTC_DATETIME
            ),
            custom_properties={"dummy": True},
        )
        # Attachments relations are later redirected to the real stix_case
        attachments, opencti_files = self.process_attachments(case, dummy_case)

        # Now that we have the files, we create the actual object.
        stix_case = self.process_main_case(case, markings, case_object_refs)

        # Relationships generated earlier now point to stix_case, ensuring correct linkage.
        # Add if opencti_files exists
        if opencti_files:
            # We recreate a new stix_case with custom_properties
            stix_case_data = json.loads(stix_case.serialize())
            stix_case_data["custom_properties"] = {"x_opencti_files": opencti_files}
            stix_case = CustomObjectCaseIncident(**stix_case_data)

        bundle_objects.append(stix_case)
        bundle_objects.extend(self.process_tasks(case, stix_case))
        bundle_objects.extend(self.process_comments(case, stix_case))

        try:
            bundle = self.helper.stix2_create_bundle(bundle_objects)
            self.helper.log_info(
                f"Completed generation of STIX bundle for case: {case.get('title')}"
            )
            self.helper.send_stix2_bundle(bundle)

        except Exception as e:
            self.helper.log_error(f"Error serializing STIX bundle for 'case': {str(e)}")
            return {}

        # Send only STIX Artifacts in the background
        if attachments:
            try:
                self.helper.log_info("Sending STIX artifacts bundle (attachments)...")
                self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(attachments)
                )

            except Exception as e:
                self.helper.log_error(f"Error when sending artifacts: {str(e)}")

        return bundle

    def generate_sighting(self, observable, stix_observable):
        """Generate a STIX sighting from a provided observable and stix observable."""
        if observable.get("sighted"):
            int_start_date = int(observable.get("startDate")) / 1000
            stix_sighting = stix2.Sighting(
                id=StixSightingRelationship.generate_id(
                    stix_observable.id,
                    self.identity.get("standard_id"),
                    format_datetime(int_start_date, DEFAULT_UTC_DATETIME),
                    format_datetime(int_start_date + 3600, DEFAULT_UTC_DATETIME),
                ),
                first_seen=format_datetime(int_start_date, DEFAULT_UTC_DATETIME),
                last_seen=format_datetime(int_start_date + 3600, DEFAULT_UTC_DATETIME),
                where_sighted_refs=[self.identity.get("standard_id")],
                sighting_of_ref="indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e",
                custom_properties={"x_opencti_sighting_of_ref": stix_observable.id},
            )
            return stix_sighting
        return None

    def get_interval(self):
        """Get the interval in seconds."""
        return int(self.thehive_interval) * 60

    def get_last_date(self, date_key, default_date):
        """Get the last date from the current state or use the default date."""
        if date_key in self.current_state:
            last_date = self.current_state[date_key]
            self.helper.log_info(
                f"Connector ({date_key}): {format_datetime(last_date, DEFAULT_UTC_DATETIME)}"
            )
        else:
            last_date = default_date
            self.helper.log_info(
                f"Using default date ({default_date}) for ({date_key})."
            )
        return last_date

    def get_marking(self, mappings, key):
        """Get the Marking based on the mappings key."""
        return mappings.get(key, mappings[0])

    def get_updated_date(self, item, last_date):
        """Get the highest date observed within item and last_date."""
        if "_updatedAt" in item and item["_updatedAt"] is not None:
            new_date = int(item["_updatedAt"] / 1000) + 1
            self.helper.log_debug(
                f"Using '_updatedAt' for last date calculation: {last_date} new date calculation: {new_date}"
            )
        else:
            new_date = int(item.get("_createdAt") / 1000) + 1
            self.helper.log_debug(
                f"Using '_createdAt' for last date calculation: {last_date} new date calculation: {new_date}"
            )
        return max(last_date, new_date)

    def not_found_items(self, items, type):
        api_error_msg = (
            "There is an error with your The Hive URL: "
            + self.thehive_url
            + items["message"]
            + " as the type <"
            + type
            + "> is not found and the API message error is: "
            + items["type"]
        )
        raise Exception({"message": api_error_msg})

    def process_items(self, type, items, process_func, last_date_key):
        """Process items, execute process_func, and send_stix2_bundle."""
        friendly_name = f"TheHive processing ({type}) @ {datetime.now().isoformat()}"
        self.helper.log_info(f"Processing type ({type}) and ({len(items)}) item(s).")
        last_date = self.current_state.get(last_date_key, self.thehive_import_from_date)
        updated_last_date = last_date
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        for item in items:
            self.helper.log_debug(f"item: {items}")
            if str(item.get("tlp")) in self.thehive_import_only_tlp:
                stix_bundle = process_func(item)
                self.helper.send_stix2_bundle(
                    stix_bundle,
                    work_id=work_id,
                )

                updated_last_date = self.get_updated_date(item, updated_last_date)
            else:
                self.helper.log_warning(
                    f"Ignoring {item.get('title')} due to TLP too high."
                )
        message = f"Processing complete, last update: {updated_last_date}"
        self.helper.api.work.to_processed(work_id, message)
        return updated_last_date

    def process_logic(self, type, last_date_key, bundle_func):
        """Process case or alert based on returned query. Update state once complete."""
        self.helper.log_info(
            f"here the cureent state of the connector : {self.current_state}..."
        )
        last_date = self.get_last_date(last_date_key, self.thehive_import_from_date)
        self.helper.log_info(f"Last Date: {last_date}(s)...")
        query = self.construct_query(type, last_date)
        self.helper.log_info(f"Start Processing {type}(s)...")
        if type == "case":
            items: list["OutputCase"] = self.thehive_api.case.find(
                filters=query,
                sortby=Asc("_updatedAt"),
                paginate=Paginate(start=0, end=100),
            )
            if not isinstance(items, list):
                self.not_found_items(items, type)
        elif type == "alert":
            items: list["OutputAlert"] = self.thehive_api.alert.find(
                filters=query,
                sortby=Asc("_updatedAt"),
                paginate=Paginate(start=0, end=100),
            )
            if not isinstance(items, list):
                self.not_found_items(items, type)
        else:
            raise ValueError(f"Unsupported type in process_logic: {type}")
        updated_last_date = self.process_items(
            type=type,
            items=items,
            process_func=bundle_func,
            last_date_key=last_date_key,
        )
        self.helper.log_info(
            f"Updated last date: {updated_last_date} for {last_date_key}"
        )
        self.current_state.update({last_date_key: updated_last_date})
        self.helper.log_info(f"Current state updated: {self.current_state}")
        self.helper.set_state(self.current_state)

    def process_main_case(self, case, markings, object_refs=None):
        """Process Hive case and return CustomObjectCaseIncident"""
        created = format_datetime(
            int(case.get("_createdAt")) / 1000, DEFAULT_UTC_DATETIME
        )
        opencti_case_status = None
        if len(self.thehive_case_status_mapping) > 0:
            for case_status_mapping in self.thehive_case_status_mapping:
                case_status_mapping_split = case_status_mapping.split(":")
                if case.get("extendedStatus") == case_status_mapping_split[0]:
                    opencti_case_status = case_status_mapping_split[1]
        opencti_case_user = None
        if len(self.thehive_user_mapping) > 0:
            for user_mapping in self.thehive_user_mapping:
                user_mapping_split = user_mapping.split(":")
                if case.get("owner") == user_mapping_split[0]:
                    opencti_case_user = user_mapping_split[1]
        stix_case = CustomObjectCaseIncident(
            id=CaseIncident.generate_id(case.get("title"), created),
            name=case.get("title"),
            description=case.get("description"),
            created=created,
            object_marking_refs=markings,
            labels=case.get("tags") if case.get("tags") else None,
            created_by_ref=self.identity.get("standard_id"),
            severity=(
                self.severity_mapping[case.get("severity")]
                if case.get("severity") in self.severity_mapping
                else None
            ),
            x_opencti_workflow_id=opencti_case_status,
            x_opencti_assignee_ids=(
                [opencti_case_user] if opencti_case_user is not None else None
            ),
            object_refs=object_refs if object_refs is not None else [],
        )
        return stix_case

    def process_markings(self, item):
        """Process TLP and PAP and return markings."""
        return [
            self.get_marking(TLP_MAPPINGS, item.get("tlp")),
            self.get_marking(PAP_MAPPINGS, item.get("pap")),
        ]

    def process_observables(self, case, markings):
        """Process all observables from a case."""
        try:
            case_id = case.get("_id")

            self.helper.log_info(f"!!! here the value of case_id : {case_id}")
            response = self.thehive_api.case.find_observables(case_id=case.get("_id"))
            if response and len(response) > 0:
                observables = response
                self.helper.log_info(
                    f"Processing {len(observables)} observables for case: {case.get('title')}"
                )
                processed_observables = []
                object_refs = []
                i = 1
                for observable in observables:
                    self.helper.log_info(f"!!! !!! observable n° {i}")
                    i += 1
                    stix_observable = self.convert_observable(observable, markings)
                    if stix_observable:
                        if hasattr(stix_observable, "id"):
                            processed_observables.append(stix_observable)
                            object_refs.append(stix_observable.id)
                            sighting = self.generate_sighting(
                                observable, stix_observable
                            )
                            if sighting:
                                processed_observables.append(sighting)
                return processed_observables, object_refs
            else:
                self.helper.log_error(
                    f"Failed to get observables for case: {case.get('title')}"
                )
                return [], []
        except Exception as e:
            self.helper.log_error(
                f"Error processing observables for case: {case.get('title')} - {str(e)}"
            )
            return [], []

    def process_observables_and_relations(self, observable, markings, stix_incident):
        """Function to process observables and create related STIX relations."""
        try:
            stix_observable = self.convert_observable(observable, markings)
            if not stix_observable:
                return None, None
            if hasattr(stix_observable, "id"):
                stix_observable_relation = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_observable.id, stix_incident.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.identity.get("standard_id", ""),
                    source_ref=stix_observable.id,
                    target_ref=stix_incident.id,
                    object_marking_refs=markings,
                    allow_custom=True,
                )
            return stix_observable, stix_observable_relation
        except AttributeError as e:
            self.helper.log_error(
                f"Attribute error occurred: {str(e)},\nObservable: {observable}"
            )
            return stix_observable, None
        except Exception as e:
            self.helper.log_error(
                f"Error occurred: {str(e)},\nObservable: {observable}"
            )
            return stix_observable, None

    def process_tasks(self, case, stix_case):
        """Function to process all tasks within a case."""
        tasks = self.thehive_api.case.find_tasks(case_id=case.get("_id"))
        self.helper.log_info(
            f"Processing {len(tasks)} tasks for case: {case.get('title')}"
        )
        processed_tasks = []
        for task in tasks:
            created = format_datetime(
                int(task.get("_createdAt")) / 1000, DEFAULT_UTC_DATETIME
            )
            opencti_task_status = None
            if len(self.thehive_task_status_mapping) > 0:
                for task_status_mapping in self.thehive_task_status_mapping:
                    task_status_mapping_split = task_status_mapping.split(":")
                    if task.get("status") == task_status_mapping_split[0]:
                        opencti_task_status = task_status_mapping_split[1]
            opencti_task_user = None
            if len(self.thehive_user_mapping) > 0:
                for user_mapping in self.thehive_user_mapping:
                    user_mapping_split = user_mapping.split(":")
                    if task.get("assignee") == user_mapping_split[0]:
                        opencti_task_user = user_mapping_split[1]
            stix_task = CustomObjectTask(
                id=Task.generate_id(task.get("title"), created),
                name=task.get("title"),
                description=task.get("description"),
                created=created,
                due_date=(
                    format_datetime(task.get("dueDate") / 1000, DEFAULT_UTC_DATETIME)
                    if "dueDate" in task
                    else None
                ),
                object_refs=[stix_case.id],
                x_opencti_workflow_id=opencti_task_status,
                x_opencti_assignee_ids=(
                    [opencti_task_user] if opencti_task_user is not None else None
                ),
            )
            processed_tasks.append(stix_task)
        return processed_tasks

    def process_comments(self, case, stix_case):
        """Function to process all comments within a case."""
        case_comments = self.thehive_api.case.find_comments(
            case_id=case.get("_id"),
            sortby=Asc("_createdAt"),
            paginate=Paginate(start=0, end=10),
        )
        self.helper.log_info(
            f"Processing {len(case_comments)} comments for case: {case.get('title')}"
        )
        processed_comments = []
        for comment in case_comments:
            created_at = comment.get("_createdAt")
            if created_at is None:
                self.helper.log_warning(
                    f"Commentaire {comment.get('_id')} without ‘_createdAt’. Use the case creation date."
                )
                created_at = case.get("_createdAt")
                if created_at is None:
                    created_at = int(time.time() * 1000)
            created = format_datetime(int(created_at) / 1000, DEFAULT_UTC_DATETIME)
            # Creating a dictionary representing a STIX Note object
            stix_comment = {
                "type": "note",
                "id": "note--" + str(uuid.uuid4()),
                "content": comment.get("message", "No comment"),
                "created": created,
                "modified": created,
                "object_refs": [stix_case.id],
            }
            processed_comments.append(stix_comment)
        return processed_comments

    def process_attachments(self, case, stix_case):
        """
        Downloading attachments and creating STIX Artifacts objects + OpenCTI files.
        """
        case_id = case.get("_id")
        attachments = self.thehive_api.case.find_attachments(case_id=case_id)
        self.helper.log_info(
            f"Processing {len(attachments)} attachments for case: {case.get('title')}"
        )

        processed_attachments = []
        opencti_files = []

        if attachments:
            for attachment in attachments:
                file_id = attachment.get("_id")
                file_name = attachment.get("name", "unknown_file")
                content_type = attachment.get("contentType", "application/octet-stream")

                if file_id and file_name:
                    try:
                        url = f"{self.thehive_url}/api/v1/attachment/{file_id}/download"
                        self.helper.log_info(
                            f"Download attachment {file_name} depuis {url}"
                        )

                        response = requests.get(
                            url,
                            headers={"Authorization": f"Bearer {self.thehive_api_key}"},
                            verify=self.thehive_check_ssl,
                        )

                        if response.status_code != 200:
                            self.helper.log_error(
                                f"http Error {response.status_code} when downloading {file_name}"
                            )
                            continue

                        encoded_content = base64.b64encode(response.content).decode(
                            "utf-8"
                        )
                        file_artifact = stix2.Artifact(
                            mime_type=content_type,
                            payload_bin=encoded_content,
                            allow_custom=True,
                            custom_properties={"x_thehive_id": file_id},
                        )

                        artifact_relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", file_artifact.id, stix_case.id
                            ),
                            relationship_type="related-to",
                            created_by_ref=self.identity.get("standard_id", ""),
                            source_ref=file_artifact.id,
                            target_ref=stix_case.id,
                            allow_custom=True,
                        )

                        processed_attachments.append(file_artifact)
                        processed_attachments.append(artifact_relationship)

                        opencti_files.append(
                            {
                                "name": file_name,
                                "data": encoded_content,
                                "mime_type": content_type,
                                "no_trigger_import": True,
                            }
                        )

                    except Exception as ex:
                        self.helper.log_error(
                            f"Error processing attachment {file_name}: {str(ex)}"
                        )
        else:
            self.helper.log_info(
                f"No attachments found for the case {case.get('title')}"
            )

        return processed_attachments, opencti_files

    def run(self):
        """Function to process cases, alerts, and pause based on provided interval."""

        # Main connector loop — fetches cases and alerts, converts to STIX, sends to OpenCTI.
        while True:
            self.helper.log_info("Starting TheHive Connector run loop...")
            try:
                self.current_state = self.helper.get_state() or {}
                self.helper.log_info(f"Current State: {self.current_state}")
                self.process_logic("case", "last_case_date", self.generate_case_bundle)
                if self.thehive_import_alerts:
                    self.process_logic(
                        "alert", "last_alert_date", self.generate_alert_bundle
                    )
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(f"Error occurred: {str(e)}")
                traceback.print_exc()
            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)
            self.helper.log_info(
                f"End of current run loop, running next interval in {self.get_interval()} second(s)."
            )
            time.sleep(self.get_interval())


if __name__ == "__main__":
    try:
        theHiveConnector = TheHive()
        theHiveConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
