import datetime as dt
import os
import sys
import time
from datetime import datetime

import requests
from pycti import OpenCTIConnectorHelper
from stix2 import (
    Bundle,
    ExternalReference,
    Identity,
    Location,
    Relationship,
    Report,
    ThreatActor,
)


class RansomwareAPIConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        interval (str): The interval to use. It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

        # Specific connector attributes for external import connectors
        try:
            self.interval = os.environ.get("CONNECTOR_RUN_EVERY", None).lower()
            self.helper.log_info(
                f"Verifying integrity of the CONNECTOR_RUN_EVERY value: '{self.interval}'"
            )
            unit = self.interval[-1]
            if unit not in ["d", "h", "m", "s"]:
                raise TypeError
            int(self.interval[:-1])
        except TypeError as _:
            msg = f"Error ({_}) when grabbing CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively. "
            self.helper.log_error(msg)
            raise ValueError(msg)

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        if isinstance(update_existing_data, str) and update_existing_data.lower() in [
            "true",
            "false",
        ]:
            self.update_existing_data = (
                True if update_existing_data.lower() == "true" else False
            )
        elif isinstance(update_existing_data, bool) and update_existing_data.lower in [
            True,
            False,
        ]:
            self.update_existing_data = update_existing_data
        else:
            msg = f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{update_existing_data}'. It SHOULD be either `true` or `false`. `false` is assumed. "
            self.helper.log_warning(msg)
            self.update_existing_data = "false"

    def stix_object_generator(self, item):
        """Comment"""

        self.helper.log_info(f"Processing {item}.")
        threat_actor = ThreatActor(name=item["group_name"], labels=["ransomware"])

        identity = Identity(name=item["post_title"], identity_class="organisation")

        # Creating External References Object if they have external referncees
        external_references = []

        for field in ["screenshot", "website", "post_url"]:
            if item.get(field):
                external_reference = ExternalReference(
                    source_name="ransomware.live",
                    url=item[field],
                    description=f"This is the {field} for the ransomware campaign.",
                )
                external_references.append(external_reference)

        # Creating Report object
        report = Report(
            report_types=["Ransomware-report"],
            name=item.get("post_title"),
            description=item.get("description"),
            object_refs=[threat_actor.get("id")],
            published=datetime.strptime(item.get("published"), "%Y-%m-%d %H:%M:%S.%f"),
            created=datetime.strptime(item.get("discovered"), "%Y-%m-%d %H:%M:%S.%f"),
            external_references=external_references,
        )
        # Creating Relationships
        Target_attribution = Relationship(
            relationship_type="attributed-to",
            source_ref=threat_actor.get("id"),
            target_ref=identity.get("id"),
        )
        Target_relation = Relationship(
            relationship_type="targets",
            source_ref=threat_actor.get("id"),
            target_ref=identity.get("id"),
        )
        Report_relation = Relationship(
            relationship_type="related-to",
            source_ref=report.get("id"),
            target_ref=threat_actor.get("id"),
        )
        Threat_relation = Relationship(
            relationship_type="related-to",
            source_ref=threat_actor.get("id"),
            target_ref=report.get("id"),
        )

        Report_Organisation_relation = Relationship(
            relationship_type="related-to",
            source_ref=report.get("id"),
            target_ref=identity.get("id"),
        )

        # Creating Location object
        if item["country"] != "":
            location = Location(name=item["country"], country=item["country"])

            Location_relation = Relationship(
                relationship_type="located-at",
                source_ref=identity.get("id"),
                target_ref=location.get("id"),
            )

            bundle = Bundle(
                objects=[
                    report,
                    identity,
                    threat_actor,
                    location,
                    Target_attribution,
                    Target_relation,
                    Report_relation,
                    Threat_relation,
                    Report_Organisation_relation,
                    Location_relation,
                ],
                allow_custom=True,
            )
        else:
            bundle = Bundle(
                objects=[
                    report,
                    identity,
                    threat_actor,
                    Target_attribution,
                    Target_relation,
                    Report_relation,
                    Threat_relation,
                    Report_Organisation_relation,
                ],
                allow_custom=True,
            )

        self.helper.log_info(f"Sending {bundle} STIX objects to collect_intellegince.")
        return bundle

    def collect_historic_intelligence(self):
        """Collects historic intelligence from ransomware.live"""
        base_url = "https://api.ransomware.live/victims/"
        headers = {"User-Agent": "OpenCTI Connector", "accept": "application/json"}

        curent_year = int(dt.date.today().year)
        # Checking if the historic year is less than 2020 as there is no data past 2020
        if int(self.get_historic_year) < 2020:
            year = 2020
        else:
            year = int(self.get_historic_year)

        stix_bundles = []
        stix_objects = []

        for year in range(year, curent_year + 1):  # Looping through the years
            year_url = base_url + str(year)
            for month in range(1, 13):  # Looping through the months
                url = year_url + "/" + str(month)
                response = requests.get(url, headers=headers)

                try:
                    if response.status_code == 200:
                        response_json = response.json()
                        print(response.raise_for_status())

                        for item in response_json:
                            bundle = self.stix_object_generator(
                                item
                            )  # calling the stix_object_generator method to create stix objects
                            stix_bundles.append(bundle)
                            stix_objects.extend(bundle.objects)
                    else:
                        self.helper.log_info(
                            f"Error and response status code {response.status_code}"
                        )

                except Exception as e:
                    self.helper.log_error(str(e))
                    return stix_objects

        return stix_objects

    def collect_intelligence(self, last_run) -> list:
        url = "https://api.ransomware.live/recentvictims"
        headers = {"User-Agent": "OpenCTI Connector", "accept": "application/json"}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_json = response.json()
            print(response.raise_for_status())
            stix_bundles = []
            stix_objects = []

            try:
                for item in response_json:
                    created = datetime.strptime(
                        item.get("discovered"), "%Y-%m-%d %H:%M:%S.%f"
                    )
                    time_diff = int(datetime.timestamp(created)) - (int(last_run) - 30)

                    if last_run is None:
                        time_diff = 1
                    else:
                        time_diff = int(datetime.timestamp(created)) - (
                            int(last_run) - 30
                        )  # 30 seconds is added to avoid missing any data that might have caused due to code execution time

                    if time_diff > 0:
                        bundle = self.stix_object_generator(
                            item
                        )  # calling the stix_object_generator method to create stix objects
                        stix_bundles.append(bundle)
                        stix_objects.extend(bundle.objects)

                self.helper.log_info(
                    f"Sending {stix_objects} STIX objects to OpenCTI..."
                )

            except Exception as e:
                self.helper.log_error(str(e))
                return []

            if len(stix_objects) > 0:
                return stix_objects
            else:
                return None

        else:
            print("Error: ", response.status_code)
            return []

    def _get_interval(self) -> int:
        """Returns the interval to use for the connector

        This SHOULD return always the interval in seconds. If the connector is execting that the parameter is received as hoursUncomment as necessary.
        """
        unit = self.interval[-1:]
        value = self.interval[:-1]

        try:
            if unit == "d":
                # In days:
                return int(value) * 60 * 60 * 24
            elif unit == "h":
                # In hours:
                return int(value) * 60 * 60
            elif unit == "m":
                # In minutes:
                return int(value) * 60
            elif unit == "s":
                # In seconds:
                return int(value)
        except Exception as e:
            self.helper.log_error(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(e)}"
            )
            raise ValueError(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(e)}"
            )

    def run(self) -> None:
        # Main procedure
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                self.get_historic = os.environ.get(
                    "CONNECTOR_PULL_HISTORY", None
                ).lower()
                self.get_historic_year = os.environ.get(
                    "CONNECTOR_HISTORY_START_YEAR", None
                ).lower()

                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector has never run"
                    )

                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) >= self._get_interval()):
                    self.helper.log_info(f"{self.helper.connect_name} will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    # testing get_historic or pull history config variable

                    try:  # Performing the collection of intelligence
                        if last_run is None and self.get_historic:
                            bundle_objects = self.collect_historic_intelligence()
                        else:
                            bundle_objects = self.collect_intelligence(last_run)

                        # Creating Bundle

                        bundle = Bundle(
                            objects=bundle_objects, allow_custom=True
                        ).serialize()

                        # self.helper.log_info(f"Sending {bundle_objects} STIX objects to OpenCTI...")

                        self.helper.log_info(
                            f"Sending {bundle_objects} STIX objects to OpenCTI..."
                        )
                        self.helper.send_stix2_bundle(
                            bundle,
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))

                    # Store the current timestamp as a last run
                    message = (
                        f"{self.helper.connect_name} connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.log_info(message)

                    self.helper.log_debug(
                        f"Grabbing current state and update it with last_run: {timestamp}"
                    )
                    current_state = self.helper.get_state()
                    if current_state:
                        current_state["last_run"] = timestamp
                    else:
                        current_state = {"last_run": timestamp}
                    self.helper.set_state(current_state)

                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self._get_interval() / 60 / 60, 2))
                        + " hours"
                    )
                else:
                    new_interval = self._get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60, 2))
                        + " hours"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info(f"{self.helper.connect_name} connector ended")
                sys.exit(0)

            time.sleep(60)
