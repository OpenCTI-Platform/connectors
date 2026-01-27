from datetime import datetime, timedelta, timezone

import requests
import stix2
from pycti import Identity, Indicator, OpenCTIConnectorHelper, StixCoreRelationship

from .settings import ConnectorSettings


class RedFlagDomainImportConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        name = self.config.connector.name.capitalize()
        self.author = stix2.Identity(
            id=Identity.generate_id(name, "organization"),
            name="Red Flag Domains",
            identity_class="organization",
        )
        self.api_url = self.config.red_flag_domains.url

    def run(self):
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_data,
            duration_period=self.config.connector.duration_period,
        )

    def process_data(self) -> None:
        """
        Process the data
        """
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
            events_count = len(indicators) + len(observables) + len(relationships)
            message = (
                f"Connector successfully run ({events_count} events have"
                f"been processed), storing last_run as {now}"
            )
            self.helper.log_info(message)
            self.helper.set_state({"last_run": now.timestamp()})
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
                pattern_type="stix",
                pattern=pattern,
                labels=["phishing", "red-flag-domains"],
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={"x_opencti_main_observable_type": "Domain-Name"},
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
            self.helper.send_stix2_bundle(bundle, work_id=work_id)
        except Exception as e:
            self.helper.log_error(str(e))
