import os
import time
from datetime import datetime, timedelta, timezone

import requests
import stix2
import yaml
from pycti import (
    Identity,
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class RedFlagDomainImportConnector:
    def __init__(self):
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        if os.path.isfile(config_file_path):
            with open(config_file_path, "r") as f:
                config = yaml.safe_load(f)
        else:
            config = {}
        try:
            self.helper = OpenCTIConnectorHelper(config)
        except Exception as e:
            print(e)
        name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], config
        ).capitalize()
        self.author = stix2.Identity(
            id=Identity.generate_id(name, "organization"),
            name=name,
            identity_class="organization",
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        self.api_url = get_config_variable(
            "REDFLAGDOMAINS_URL",
            ["redflagdomains", "url"],
            config,
        )

    def run(self):
        while True:
            try:
                current_state = self.helper.get_state()
                now = datetime.now(tz=timezone.utc)
                friendly_name = "Red Flag Domains run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                if current_state is not None and "last_run" in current_state:
                    last_seen = datetime.fromtimestamp(current_state["last_run"])
                    self.helper.log_info(f"Connector last ran at: {last_seen} (UTC)")
                else:
                    self.helper.log_info("Connector has never run")

                domain_list = self.get_domains(self.api_url)
                observables = self.create_observables(domain_list)
                indicators = self.create_indicators(observables)
                relationships = self.create_relationships(observables, indicators)
                bundle = self.create_bundle(observables, indicators, relationships)
                self.send_bundle(bundle, work_id)

                message = (
                    "Connector successfully run ("
                    + str((len(indicators) + len(observables) + len(relationships)))
                    + " events have been processed), storing last_run as "
                    + str(now)
                )
                self.helper.log_info(message)
                self.helper.set_state(
                    {
                        "last_run": now.timestamp(),
                    }
                )

                time_now = datetime.now(timezone(timedelta(hours=2)))
                time_until_2am = timedelta(
                    days=1,
                    hours=2 - time_now.hour,
                    minutes=-time_now.minute,
                    seconds=-time_now.second,
                )
                time.sleep(time_until_2am.total_seconds())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)

            except Exception as exception:
                self.helper.log_error(str(exception))

    def get_domains(self, url):
        self.helper.log_info("Enumerating domains")
        try:
            yesterday_date = datetime.now() - timedelta(days=1)
            yesterday_date_str = yesterday_date.strftime("%Y-%m-%d")
            file_url = f"{url}/{yesterday_date_str}.txt"
            response = requests.get(file_url)
            if response.status_code == 200:
                domain_list = []
                for line in response.text.split("\n"):
                    if line.strip():
                        domain_list.append(line)
                return domain_list
            else:
                self.helper.log_error(
                    f"Failed to retrieve file from {file_url}: {response.status_code}"
                )
        except Exception as e:
            self.helper.log_error(f"Error while fetching domains: {str(e)}")

    def create_observables(self, domain_list):
        self.helper.log_info("Creating STIX Observables")
        observables = []
        for domain in domain_list:
            observable = stix2.DomainName(
                value=domain,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "x_opencti_description": "Malicious domain",
                    "x_opencti_created_by_ref": f"{self.author.id}",
                    "x_opencti_labels": ["phishing", "red-flag-domains"],
                },
            )
            observables.append(observable)
        return observables

    def create_indicators(self, observables):
        self.helper.log_info("Creating STIX Indicators")
        indicators = []
        for observable in observables:
            pattern = f"[domain-name:value = '{observable.value}']"
            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=observable.value,
                description="Malicious domain",
                created_by_ref=f"{self.author.id}",
                confidence=self.helper.connect_confidence_level,
                pattern_type="stix",
                pattern=pattern,
                labels=["phishing", "red-flag-domains"],
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "x_opencti_main_observable_type": "Domain-Name",
                },
            )
            indicators.append(indicator)
        return indicators

    def create_relationships(self, observables, indicators):
        self.helper.log_info("Creating STIX Relationships")
        relationships = []
        for i in range(len(observables)):
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", indicators[i].id, observables[i].id
                ),
                relationship_type="based-on",
                source_ref=indicators[i].id,
                target_ref=observables[i].id,
                object_marking_refs=[stix2.TLP_WHITE],
            )
            relationships.append(relationship)
        return relationships

    def create_bundle(self, observables, indicators, relationships):
        self.helper.log_info("Creating STIX Bundle")
        objects = [self.author]
        for observable in observables:
            objects.append(observable)
        for indicator in indicators:
            objects.append(indicator)
        for relationship in relationships:
            objects.append(relationship)
        bundle = self.helper.stix2_create_bundle(objects)
        return bundle

    def send_bundle(self, bundle, work_id):
        self.helper.log_info("Sending STIX Bundle")
        try:
            self.helper.send_stix2_bundle(
                bundle, work_id=work_id, update=self.update_existing_data
            )
        except Exception as e:
            self.helper.log_error(str(e))


if __name__ == "__main__":
    try:
        RedFlagDomainImportConnector = RedFlagDomainImportConnector()
        RedFlagDomainImportConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
