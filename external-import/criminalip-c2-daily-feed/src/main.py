import csv
import os
import time
from datetime import datetime

import pycountry
import requests
import stix2
import yaml
from pycti import (
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class CriminalIPC2DailyFeedConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.interval = get_config_variable(
            "CRIMINALIP_INTERVAL", ["criminalipc2dailyfeed", "interval"], config, True
        )
        self.score = get_config_variable(
            "CRIMINALIP_CONFIDENCE_SCORE",
            ["criminalipc2dailyfeed", "score"],
            config,
            True,
        )
        self.csv_url = get_config_variable(
            "CRIMINALIP_CSV_URL", ["criminalipc2dailyfeed", "csv_url"], config
        )
        # Identity for Criminal IP
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Criminal IP C2 Daily Feed",
            description="Daily C2 Feed from Criminal IP",
        )

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def build_csv_url(self, target_date):
        return f"{self.csv_url}/{target_date}.csv"

    def get_country_name(self, code):
        country = pycountry.countries.get(alpha_2=code.upper())
        return country.name if country else None

    def run(self):
        self.helper.log_info("[CriminalIPC2DailyFeed] Starting connector run...")
        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")

                if last_run is None or (
                    (timestamp - last_run) > (int(self.interval) * 60 * 60 * 24)
                ):
                    # Initiate the run
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcnow()
                    file_date = now.strftime("%Y-%m-%d")
                    url = self.build_csv_url(file_date)

                    self.helper.log_info(f"Checking CSV feed for date: {file_date}")
                    response = requests.get(url)

                    if response.status_code != 200:
                        self.helper.log_info(
                            f"Feed for {file_date} not available yet. Skipping run."
                        )
                        time.sleep(60)
                        continue

                    csv_data = response.text.strip().splitlines()
                    reader = csv.DictReader(csv_data)
                    bundle_objects = []

                    for row in reader:
                        ip = row.get("IP")
                        if not ip:
                            continue
                        confidence = int(self.score)
                        raw_c2 = row.get("Target C2", "")
                        c2 = raw_c2.split("_")[1] if "_" in raw_c2 else raw_c2
                        country_code = row.get("Country", "").strip().upper()
                        description = f"CriminalIP C2 Feed - Traffic seen on port {row.get('OpenPorts', 'Unknown')}"
                        pattern = f"[ipv4-addr:value = '{ip}']"
                        stix_indicator = stix2.Indicator(
                            id=Indicator.generate_id(pattern),
                            name=f"{c2} IP - {ip}",
                            pattern_type="stix",
                            pattern=pattern,
                            confidence=confidence,
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[stix2.TLP_WHITE],
                            labels=[c2],
                            custom_properties={
                                "x_opencti_main_observable_type": "IPv4-Addr",
                                "x_opencti_score": confidence,
                            },
                            description=description,
                        )
                        stix_observable = stix2.IPv4Address(
                            value=ip,
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={
                                "created_by_ref": self.identity["standard_id"],
                                "x_opencti_score": confidence,
                                "x_opencti_description": description,
                                "x_opencti_labels": [c2],
                            },
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", stix_indicator.id, stix_observable.id
                            ),
                            relationship_type="based-on",
                            source_ref=stix_indicator.id,
                            target_ref=stix_observable.id,
                            object_marking_refs=[stix2.TLP_WHITE],
                        )
                        bundle_objects.extend(
                            [stix_indicator, stix_observable, relationship]
                        )

                        location_ref = None
                        if country_code:
                            location = self.helper.api.location.create(
                                name=self.get_country_name(country_code),
                                type="Country",
                                x_opencti_aliases=[country_code],
                                x_opencti_location_type="Country",
                            )
                            if location:
                                location_ref = location["standard_id"]
                        if location_ref:
                            located_at = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "located-at", stix_observable.id, location_ref
                                ),
                                relationship_type="located-at",
                                source_ref=stix_observable.id,
                                target_ref=location_ref,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            bundle_objects.append(located_at)

                    self.helper.log_info("Creating STIX Bundle")
                    self.helper.log_debug(f"Bundle: {bundle_objects}")
                    bundle = self.helper.stix2_create_bundle(bundle_objects)
                    self.helper.log_info("Sending STIX Bundle")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id,
                        f"Criminal IP C2 feed import {file_date}",
                    )
                    self.helper.send_stix2_bundle(bundle, work_id=work_id)
                    self.helper.set_state({"last_run": int(time.time())})
                    self.helper.api.work.to_processed(
                        work_id, f"Imported C2 data from {file_date}"
                    )
                    self.helper.log_info(
                        "Run complete successfully. Next run in 24 hours."
                    )
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
            except Exception as e:
                self.helper.log_error(f"Error during run: {str(e)}")
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = CriminalIPC2DailyFeedConnector()
        connector.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        time.sleep(10)
        exit(0)
