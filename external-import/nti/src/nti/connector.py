import ipaddress
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector
from .converter_to_stix import ConverterToStix


class NTIConnector:
    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        self.work_id = ''
        # read config file
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.config.initialize_configurations(self.helper)
        # get env variables
        self.package_type = self.config.package_type
        self.create_tasks = self.config.create_tasks

        self.helper.connector_logger.info("[CONNECTOR] tasks initialized.", {"initialized tasks": self.create_tasks})
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def _collect_intelligence(self) -> None:
        """
        Collect intelligence from the source and convert into STIX object
        """
        switcher = {
            "data.NTI.API.V2.0.ioc-updated": self.create_ioc,
            "data.NTI.API.V2.0.ip-basic-updated": self.create_ip_basic,
            "data.NTI.API.V2.0.domain-basic-updated": self.create_domain_basic,
            "data.NTI.API.V2.0.url-basic-updated": self.create_url_basic,
            "data.NTI.API.V2.0.sample-updated": self.create_sample_basic,
        }
        for intelligence_data, entity_type in self.client.acquire_feed_packages(self.create_tasks):
            # call corresponding functions
            handler = switcher.get(entity_type)
            object_count = handler(intelligence_data)
            self.helper.connector_logger.info(
                f"{object_count} {entity_type} objects were sent to OpenCTI.",
            )

    def start_work(self, entity_type: str) -> None:
        """
        start work
        """

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = f"NTI {entity_type} feed"
        self.helper.connector_logger.info(
            f"Starting work: {friendly_name}",
        )
        # Initiate a new work
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting work",
            {"Connector name": self.helper.connect_name},
        )

    def end_work(self) -> None:
        """
        end of work, record work info
        """
        now = datetime.now()
        current_timestamp = int(datetime.timestamp(now))
        # Store the current timestamp as a last run of the connector
        self.helper.connector_logger.debug(
            "Getting current state and update it with last run of the connector",
            {"current_timestamp": current_timestamp},
        )
        current_state = self.helper.get_state()
        current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
        last_run_datetime = datetime.fromtimestamp(
            current_timestamp, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        if current_state:
            current_state["last_run"] = current_state_datetime
        else:
            current_state = {"last_run": current_state_datetime}
        self.helper.set_state(current_state)

        message = (
            f"{self.helper.connect_name} connector successfully run, storing last_run as "
            + str(last_run_datetime)
        )
        self.helper.api.work.to_processed(self.work_id, message)
        self.helper.connector_logger.info(message)

    def send_stix2_bundle(self, stix_objects: list) -> None:
        if stix_objects:
            stix_objects.extend(
                [self.converter_to_stix.author, self.converter_to_stix.tlp_marking]
            )
            stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(
                stix_objects_bundle,
                work_id=self.work_id,
                cleanup_inconsistent_bundle=True,
            )
        else:
            raise ValueError("No STIX objects found")

    def create_url_basic(self, url_basics: list) -> int:
        # fetch url data from json file
        url_count = 0
        url_stix_objects = []
        self.helper.connector_logger.info(
            f"[CONNECTOR] {len(url_basics)} url object were found"
        )
        # if find data
        if url_basics:
            self.start_work("URL")
        else:
            return url_count
        for url_basic in url_basics:
            # create stix2 url object
            url = self.converter_to_stix.create_obs(url_basic)
            url_stix_objects.append(url)
            url_count += 1
        # send in one bundle will tremendously reduce number of ops for OpenCTI
        self.send_stix2_bundle(url_stix_objects)
        self.end_work()
        return url_count

    def create_sample_basic(self, sample_basics: list) -> int:
        sample_stix_objects = []
        self.helper.connector_logger.info(
            f"[CONNECTOR] {len(sample_basics)} sample object were found"
        )
        sample_count = 0
        # if find data
        if sample_basics:
            self.start_work("File")
        else:
            return sample_count
        for sample_basic in sample_basics:
            # create stix2 file object
            sample = self.converter_to_stix.create_obs(sample_basic)
            sample_stix_objects.append(sample)
            sample_count += 1
        self.send_stix2_bundle(sample_stix_objects)
        self.end_work()
        return sample_count

    def create_domain_basic(self, domain_basics: list) -> int:
        domain_stix_objects = []
        self.helper.connector_logger.info(
            f"[CONNECTOR] {len(domain_basics)} domain object were found"
        )
        domain_count = 0
        # if find data
        if domain_basics:
            self.start_work("Domain")
        else:
            return domain_count
        relationship_list = []
        for domain_basic in domain_basics:
            # create stix2 domain-name object
            domain = self.converter_to_stix.create_obs(domain_basic)
            domain_stix_objects.append(domain)
            domain_count += 1
            for ip in domain_basic.get("ips", []):
                # construct ip observable to fit create_obs(ip) function
                if self._is_ipv6(ip.get("ips", [""])[0]):
                    ip["object"] = {
                        "type": "ipv6-addr",
                        "value": ip.get("ips", [""])[0],
                    }
                else:
                    ip["object"] = {
                        "type": "ipv4-addr",
                        "value": ip.get("ips", [""])[0],
                    }
                ip_object = self.converter_to_stix.create_obs(ip)
                domain_stix_objects.append(ip_object)
                description = [
                    "This relationship illustrates a domain name resolves to this ip address"
                ]
                if ip.get("first_seen"):
                    description.append(f"first observed on {ip.get('first_seen')}")
                if ip.get("last_seen"):
                    description.append(f"last seen on {ip.get('last_seen')}")
                description = ", ".join(description) + "."
                relationship = self.converter_to_stix.create_relationship(
                    source_id=domain.id,
                    relationship_type="resolves-to",
                    target_id=ip_object.id,
                    start_time=ip.get("first_seen"),
                    description=description,
                )
                relationship_list.append(relationship)
        self.send_stix2_bundle(domain_stix_objects)
        self.send_stix2_bundle(relationship_list)
        self.end_work()
        return domain_count

    def create_ip_basic(self, ip_basics: list) -> int:
        ip_stix_objects = []
        self.helper.connector_logger.info(
            f"[CONNECTOR] {len(ip_basics)} ip object were found"
        )
        ip_count = 0
        # if find data
        if ip_basics:
            self.start_work("IP")
        else:
            return ip_count
        relationship_list = []
        for ip_basic in ip_basics:
            # create stix2 ipv4-addr object
            observable = self.converter_to_stix.create_obs(ip_basic)
            ip_stix_objects.append(observable)
            ip_count += 1
            locations = self.converter_to_stix.create_location(
                ip_basic.get("locations", [])
            )
            ip_stix_objects.extend(locations)
            for location in locations:
                relationship = self.converter_to_stix.create_relationship(
                    source_id=observable.id,
                    relationship_type="located-at",
                    target_id=location.id,
                    start_time=ip_basic.get("modified"),
                    description="This relationship illustrates an ipv4 address is located at this location.",
                )
                relationship_list.append(relationship)
            ases = self.converter_to_stix.create_AutonomousSystem(
                ip_basic.get("ases", [])
            )
            ip_stix_objects.extend(ases)
            for asn in ases:
                relationship = self.converter_to_stix.create_relationship(
                    source_id=observable.id,
                    relationship_type="belongs-to",
                    target_id=asn.id,
                    start_time=asn.get("first_seen"),
                    description="This relationship illustrates an ipv4 address belongs to an autonomous system.",
                )
                relationship_list.append(relationship)
        self.send_stix2_bundle(ip_stix_objects)
        self.send_stix2_bundle(relationship_list)
        self.end_work()
        return ip_count

    def create_ioc(self, indicators: list) -> int:
        ioc_stix_objects = []
        # fetch indicator data from json file
        self.helper.connector_logger.info(
            f"[CONNECTOR] {len(indicators)} IOC object were found"
        )
        IOC_count = 0
        # if find data
        if indicators:
            self.start_work("IOC")
        else:
            return IOC_count
        # Convert into STIX2 object and add it on a list
        relationship_list = []
        for indicator in indicators:
            # create stix2 indicator object
            indicator_object = self.converter_to_stix.create_indicator(indicator)
            if not indicator_object:
                continue
            ioc_stix_objects.append(indicator_object)
            IOC_count += 1
            observable = self.converter_to_stix.create_obs(indicator)
            ioc_stix_objects.append(observable)
            relationship = self.converter_to_stix.create_relationship(
                source_id=indicator_object.id,
                relationship_type="based-on",
                target_id=observable.id,
                start_time=indicator_object.modified,
                description="This relationship demonstrates an indicator based on this observable.",
            )
            relationship_list.append(relationship)
        self.send_stix2_bundle(ioc_stix_objects)
        # deal with MISSING_REFERENCE_ERROR
        self.send_stix2_bundle(relationship_list)
        self.end_work()
        return IOC_count

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv6
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"NTIConnector": self.helper.connect_name},
        )
        try:
            # Get the current state
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )
            self.helper.connector_logger.info(
                "[CONNECTOR] Fetching feed packages...",
                {"feed package type": self.package_type},
            )
            # Performing the collection of intelligence
            self._collect_intelligence()

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"NTIConnector": self.helper.connect_name},
            )
            raise
        except Exception as err:
            self.helper.api.work.to_processed(
                self.work_id,
                f"[CONNECTOR] Data collection failed: {str(err)}",
                in_error=True
            )
            self.helper.connector_logger.error(str(err))
            raise

    def run(self) -> None:
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
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
