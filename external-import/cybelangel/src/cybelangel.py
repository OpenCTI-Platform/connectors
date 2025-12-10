import os
import sys
import time
from datetime import datetime, timedelta, timezone

import requests
import stix2
import yaml
from pycti import (
    Campaign,
    Identity,
    IntrusionSet,
    Location,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class CybelAngel:
    """Main class for the CybelAngel OpenCTI connector."""

    def __init__(self):
        """
        Initialize the CybelAngel connector by loading configuration and setting up the OpenCTI helper.

        """

        # Instantiate the connector helper from config
        try:
            config_file_path = (
                os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
            )
            config_file_path = config_file_path.replace("\\", "/")
            config = (
                yaml.load(open(config_file_path), Loader=yaml.FullLoader)
                if os.path.isfile(config_file_path)
                else {}
            )

            self.helper = OpenCTIConnectorHelper(config)

            # Extra config
            self.opencti_url = get_config_variable(
                "OPENCTI_URL", ["opencti", "url"], config, default="http://opencti:8080"
            )
            self.opencti_token = get_config_variable(
                "OPENCTI_TOKEN", ["opencti", "token"], config
            )
            self.connector_id = get_config_variable(
                "CONNECTOR_ID", ["connector", "id"], config
            )
            self.connector_type = get_config_variable(
                "CONNECTOR_TYPE",
                ["connector", "type"],
                config,
                default="EXTERNAL_IMPORT",
            )
            self.connector_name = get_config_variable(
                "CONNECTOR_NAME", ["connector", "name"], config, default="CybelAngel"
            )
            self.connector_scope = get_config_variable(
                "CONNECTOR_SCOPE", ["connector", "scope"], config, default="all"
            )
            self.connector_log_level = get_config_variable(
                "CONNECTOR_LOG_LEVEL",
                ["connector", "log_level"],
                config,
                default="error",
            )
            self.cybelangel_client_id = get_config_variable(
                "CYBELANGEL_CLIENT_ID", ["cybelangel", "client_id"], config
            )
            self.cybelangel_client_secret = get_config_variable(
                "CYBELANGEL_CLIENT_SECRET", ["cybelangel", "client_secret"], config
            )
            self.cybelangel_api_url = get_config_variable(
                "CYBELANGEL_API_URL",
                ["cybelangel", "api_url"],
                config,
                default="https://api.cybelangel.com",
            )
            self.cybelangel_auth_url = get_config_variable(
                "CYBELANGEL_AUTH_URL",
                ["cybelangel", "auth_url"],
                config,
                default="https://auth.cybelangel.com/oauth/token",
            )
            self.cybelangel_interval = get_config_variable(
                "CYBELANGEL_INTERVAL",
                ["cybelangel", "interval"],
                config,
                isNumber=True,
                default=1,
            )
            self.cybelangel_marking = get_config_variable(
                "CYBELANGEL_MARKING",
                ["cybelangel", "marking"],
                config,
                default="TLP:AMBER+STRICT",
            )
            self.cybelangel_fetch_period = get_config_variable(
                "CYBELANGEL_FETCH_PERIOD",
                ["cybelangel", "fetch_period"],
                config,
                default="7",
            )
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error loading configuration: {e}. Please check your config.yml file."
            )
            sys.exit(1)

    def load_marking_definition(self):
        """
        Load or create a STIX MarkingDefinition object based on the configured TLP level.

        Supports standard TLP levels: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT and TLP:RED.
        TLP:CLEAR and TLP:AMBER+STRICT are handled as custom markings since they are not natively supported in STIX2.

        Returns:
            None
        """
        try:
            tlp_value = self.cybelangel_marking.upper()
            self.helper.connector_logger.debug(f"Configured TLP marking: {tlp_value}")

            if tlp_value == "TLP:CLEAR":
                marking = stix2.MarkingDefinition(
                    id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                    definition_type="statement",
                    definition={"statement": "TLP:CLEAR"},
                    allow_custom=True,
                    x_opencti_definition_type="TLP",
                    x_opencti_definition="TLP:CLEAR",
                )
            elif tlp_value in ["TLP:GREEN", "TLP:AMBER", "TLP:RED"]:
                marking = stix2.MarkingDefinition(
                    definition_type="tlp",
                    definition={"tlp": tlp_value.split(":")[1].lower()},
                    x_opencti_definition_type="TLP",
                    x_opencti_definition=tlp_value,
                )
            elif tlp_value == "TLP:AMBER+STRICT":
                marking = stix2.MarkingDefinition(
                    id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                    definition_type="statement",
                    definition={"statement": "TLP:AMBER+STRICT"},
                    allow_custom=True,
                    x_opencti_definition_type="TLP",
                    x_opencti_definition="TLP:AMBER+STRICT",
                )
            else:
                self.helper.connector_logger.warning(
                    f"Unsupported TLP marking '{tlp_value}', defaulting to TLP:AMBER+STRICT"
                )
                marking = stix2.MarkingDefinition(
                    id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                    definition_type="tlp",
                    definition={"statement": "TLP:AMBER+STRICT"},
                    allow_custom=True,
                    x_opencti_definition_type="TLP",
                    x_opencti_definition="TLP:AMBER+STRICT",
                )

            self.cybelangel_marking = marking
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error loading marking definition: {e}. Please check your configuration. Using default "
                f"TLP:AMBER+STRICT. "
            )
            self.cybelangel_marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "TLP:AMBER+STRICT"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )

    def authenticate(self, max_retries=3, delay=5):
        """
        Authenticate with the CybelAngel API using client credentials and retrieve an access token.
        Retries on failure up to `max_retries` times with `delay` seconds between attempts.

        Args:
            None

        Returns:
            str: A valid OAuth2 bearer token if authentication is successful, otherwise None.

        Raises:
            Exception: If the authentication request fails or the response is invalid.
            :param delay:
            :param max_retries:
        """

        auth_data = {
            "client_id": self.cybelangel_client_id,
            "client_secret": self.cybelangel_client_secret,
            "audience": "https://platform.cybelangel.com/",
            "grant_type": "client_credentials",
        }

        headers = {
            "Content-Type": "application/json",
            "User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/138.0.0.0 Safari/537.36 ",
        }
        for attempt in range(1, max_retries + 1):
            self.helper.connector_logger.info(
                f"Attempt {attempt} to authenticate with CybelAngel API"
            )
            try:
                response = requests.post(
                    self.cybelangel_auth_url, json=auth_data, headers=headers
                )
                response.raise_for_status()
                token_data = response.json()
                if "access_token" in token_data:
                    self.helper.connector_logger.info("Authentication successful")
                    return token_data["access_token"]
                else:
                    self.helper.connector_logger.error(
                        f"Authentication failed: {token_data}"
                    )
                    return None
            except requests.exceptions.RequestException as e:
                self.helper.connector_logger.error(
                    f"Error during authentication attempt {attempt}: {e}"
                )
                self.helper.connector_logger.info(
                    f"Retrying in {delay} seconds... (Attempt {attempt}/{max_retries})"
                )
                if attempt < max_retries:
                    time.sleep(delay)

    def create_cybelangel_org(self):
        """
        Creates an identity object for the CybelAngel organization.

        This function generates a STIX 2.1 Identity object representing the CybelAngel organization. The identity includes details such as the name, description, confidence level, identity class, type, and object marking references.

        """
        try:
            identity = stix2.Identity(
                id=Identity.generate_id("CybelAngel", "Organization"),
                spec_version="2.1",
                name="CybelAngel",
                description="Cybelangel is a cybersecurity company that specializes in detecting and mitigating cyber "
                "threats.",
                confidence=50,
                identity_class="organization",
                type="identity",
                object_marking_refs=(
                    [self.cybelangel_marking.id] if self.cybelangel_marking else None
                ),
            )
            self.helper.connector_logger.debug(
                "CybelAngel identity object created successfully."
            )

            return identity
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error creating CybelAngel organization identity: {e}"
            )
            return None

    # ----------------------
    # STIX Builder
    # ----------------------
    def _create_identity(
        self, name, identity_class, marking=None, created_by=None, contact_info=None
    ):
        if not name:
            return None
        if len(name) < 2:
            self.helper.connector_logger.warning(
                f"Identity name '{name}' is too short, adding whitespace."
            )
            name += " "
        return stix2.Identity(
            id=Identity.generate_id(name, identity_class),
            name=name,
            identity_class=identity_class,
            contact_information=contact_info,
            object_marking_refs=marking,
            created_by_ref=created_by,
        )

    def _create_relationship(
        self,
        rel_type,
        source_id,
        target_id,
        published_at,
        marking=None,
        created_by=None,
    ):
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            source_ref=source_id,
            target_ref=target_id,
            created=published_at,
            relationship_type=rel_type,
            object_marking_refs=marking,
            created_by_ref=created_by,
        )

    # ----------------------
    # Fetch Data
    # ----------------------
    def opencti_bundle(self, work_id, last_run=None):
        token = self.authenticate()
        self.helper.connector_logger.debug(
            "Token received, proceeding with data fetching."
        )
        cybelangel_org_identity = self.create_cybelangel_org()

        if not token or not cybelangel_org_identity:
            self.helper.connector_logger.error("Missing token or CybelAngel identity.")
            return

        since_date, end_date, parameters = self._build_fetch_parameters(last_run)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        self._fetch_and_process_pages(
            headers, parameters, cybelangel_org_identity, work_id, since_date
        )

    def _build_fetch_parameters(self, last_run):
        if last_run:
            try:
                since_date = datetime.fromisoformat(last_run)
            except ValueError:
                fetch_period = getattr(self, "cybelangel_fetch_period", "7")
                since_date = datetime.now(timezone.utc) - timedelta(days=fetch_period)
                since_date = since_date.replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
                self.helper.connector_logger.warning(
                    f"Invalid last_run format. Using last {fetch_period} days."
                )
        else:
            fetch_period = getattr(self, "cybelangel_fetch_period", "all")
            if fetch_period == "all":
                return None, None, "sort_by=-published_at"
            days = int(fetch_period)
            since_date = datetime.now(timezone.utc) - timedelta(days=days)
            since_date = since_date.replace(hour=0, minute=0, second=0, microsecond=0)

        end_date = datetime.now(timezone.utc)
        parameters = (
            f"sort_by=-published_at"
            f"&published_at_range={since_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            f"~{end_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        return since_date, end_date, parameters

    def _fetch_and_process_pages(
        self, headers, parameters, author_org, work_id, since_date
    ):
        page_offset = 0
        page_limit = 50
        has_more = True
        attempt = 0

        while has_more:
            url = f"{self.cybelangel_api_url}/api/v1/claimed-attacks?page_offset={page_offset}&page_limit={page_limit}&{parameters}"
            self.helper.connector_logger.debug(
                f"Fetching data from CybelAngel API: {url}"
            )
            response = requests.get(url, headers=headers)

            # The CybelAngel token expires after 1 hour. This block reauthenticates in case the token is no longer valid
            if response.status_code == 401 and attempt < 3:
                attempt += 1
                self.helper.connector_logger.info(
                    f"Token expired, re-authenticating. Attempt {attempt}..."
                )
                token = self.authenticate()
                if not token:
                    self.helper.connector_logger.error(
                        "Re-authentication failed, exiting."
                    )
                    return
                headers["Authorization"] = f"Bearer {token}"
                self.helper.connector_logger.info(
                    "Re-authentication successful, retrying data fetch."
                )
                attempt = 0  # Reset attempt counter on successful response
                continue
            elif response.status_code != 200:
                self.helper.connector_logger.error(
                    f"Failed to fetch data from CybelAngel: {response.status_code}. Response: {response.text}. "
                    f"Retrying..."
                )
                time.sleep(5)
                attempt += 1
                if attempt >= 3:
                    self.helper.connector_logger.error(
                        "Failed to fetch data after 3 attempts, exiting."
                    )
                    return
                continue

            attacks = response.json().get("claimed_attacks", [])
            if not attacks:
                has_more = False
                self.helper.connector_logger.info(
                    "No more attacks found, stopping processing."
                )
                break

            self.helper.connector_logger.info(
                f"Processing {len(attacks)} attacks - offset {page_offset} with limit {page_limit}"
            )

            for attack in attacks:
                self._process_attack(attack, since_date, author_org, work_id)

            page_offset += page_limit

    # ----------------------
    # Parse & Ingest Data
    # ----------------------
    def _process_attack(self, attack, since_date, author_org, work_id):
        published_at = attack.get("published_at")
        if published_at:
            try:
                published_at = datetime.strptime(
                    published_at, "%Y-%m-%dT%H:%M:%S.%fZ"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                published_at = datetime.strptime(
                    published_at, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)

        if since_date and published_at < since_date:
            self.helper.connector_logger.info(
                f"Stopping processing as published_at {published_at.strftime('%Y-%m-%dT%H:%M:%SZ')} is before "
                f"last_run value {since_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
            return

        stix_objects = [author_org, self.cybelangel_marking]
        author_org_id = author_org["id"] if author_org else None
        marking_id = [self.cybelangel_marking.id] if self.cybelangel_marking else None

        campaign_objective = attack.get("category", "Unknown")
        if "DDOS" in campaign_objective.lower():
            resource_level = "Contest"
        else:
            resource_level = "Organization"

        threat_actors = attack.get("threat_actors", [])
        victim_countries = attack.get("victim_countries", [])
        victim_industries = attack.get("victim_industries", [])
        victim_organizations = attack.get("victim_organizations", [])
        victim_sites = attack.get("victim_sites", [])

        # Handle Campaign modelization
        final_actor = (
            threat_actors[0] if threat_actors and threat_actors[0] else "Unknown actor"
        )

        if published_at:
            published_date = datetime.strptime(published_at[:10], "%Y-%m-%d").date()
            campaign_date = f" ({published_date})"
        else:
            campaign_date = ""
        if victim_organizations:
            if len(victim_organizations) > 1:
                campaign_name = f"{final_actor} targets multiple organizations - {campaign_date}".rstrip(" - ")
                campaign_description = (
                    f"{campaign_objective.capitalize()} campaign by {final_actor} targeting multiple "
                    f"organizations: {', '.join(victim_organizations)} "
                )
            else:
                campaign_name = f"{final_actor} targets {victim_organizations[0]} - {campaign_date}".rstrip(" - ")
                campaign_description = f"{campaign_objective.capitalize()} campaign by {final_actor} targeting {victim_organizations[0]}"
        else:
            campaign_name = f"{campaign_objective.capitalize()} campaign by {final_actor} - {campaign_date}".rstrip(" - ")
            campaign_description = f"{campaign_objective.capitalize()} campaign by {final_actor} with no specific target"

        campaign = stix2.Campaign(
            id=Campaign.generate_id(campaign_name),
            name=campaign_name,
            description=campaign_description,
            created=published_at,
            first_seen=published_at,
            last_seen=published_at,
            objective=campaign_objective,
            object_marking_refs=marking_id,
            created_by_ref=author_org_id,
        )
        stix_objects.append(campaign)

        # Handle Location modelization
        locations = []
        for country in victim_countries:
            if not country:
                continue
            location = stix2.Location(
                id=Location.generate_id(country, "Country"),
                name=country,
                type="location",
                country=country,
                object_marking_refs=marking_id,
                created_by_ref=author_org_id,
            )
            locations.append(location)
            stix_objects.append(location)

            # Create relationships
            relationship_campaign_location = self._create_relationship(
                "targets",
                campaign.id,
                location.id,
                published_at,
                marking_id,
                author_org_id,
            )
            stix_objects.append(relationship_campaign_location)

        # Handle Organization modelization
        # Logic:
        # - If len(victim_organizations) and len(victim_sites) are equal put victim_sites as contact_information
        # - If len(victim_organizations) and len(victim_sites) are NOT equal put ignore victim_sites
        # - If victim_organizations is empty, use victim_sites as name (no contact_information)

        identities = []
        if victim_sites:
            if victim_organizations:
                if len(victim_sites) == len(victim_organizations):
                    for org, site in zip(victim_organizations, victim_sites):
                        if len(org) < 2:
                            self.helper.connector_logger.info(
                                f"Victim organization name {org} is too short, adding whitespace."
                            )
                            org = org + " "

                        identity = self._create_identity(
                            org, "Organization", marking_id, author_org_id, site
                        )
                        identities.append(identity)
                        stix_objects.append(identity)

                elif len(victim_sites) != len(victim_organizations):
                    for org in victim_organizations:
                        if len(org) < 2:
                            self.helper.connector_logger.info(
                                f"Victim organization name {org} is too short, adding whitespace."
                            )
                            org = org + " "

                        identity = self._create_identity(
                            org, "Organization", marking_id, author_org_id
                        )
                        identities.append(identity)
                        stix_objects.append(identity)

            else:
                for site in victim_sites:
                    if len(site) < 2:
                        self.helper.connector_logger.info(
                            f"Victim site name {site} is too short, adding whitespace."
                        )
                        site = site + " "

                    identity = self._create_identity(
                        site, "Organization", marking_id, author_org_id
                    )
                    identities.append(identity)
                    stix_objects.append(identity)

            # Create relationships
            for identity in identities:
                relationship_campaign_identity = self._create_relationship(
                    "targets",
                    campaign.id,
                    identity.id,
                    published_at,
                    marking_id,
                    author_org_id,
                )
                stix_objects.append(relationship_campaign_identity)

                for location in locations:
                    relationship_identity_location = self._create_relationship(
                        "located-at",
                        identity.id,
                        location.id,
                        published_at,
                        marking_id,
                        author_org_id,
                    )
                    stix_objects.append(relationship_identity_location)

        # Handle Sector modelization
        industries = []
        for industry in victim_industries:
            sector = self._create_identity(industry, "class", marking_id, author_org_id)
            industries.append(sector)
            stix_objects.append(sector)

            # Create relationships
            relationship_campaign_industry = self._create_relationship(
                "targets",
                campaign.id,
                sector.id,
                published_at,
                marking_id,
                author_org_id,
            )
            stix_objects.append(relationship_campaign_industry)

        # Handle Intrusion Sets modelization
        for actor in threat_actors:
            if not actor:
                continue
            if len(actor) < 2:
                self.helper.connector_logger.info(
                    f"Intrusion set name {actor} is too short, adding whitespace."
                )
                actor = actor + " "

            intrusion_set = stix2.IntrusionSet(
                id=IntrusionSet.generate_id(actor),
                name=actor,
                description=f"Threat actor {actor} from CybelAngel",
                resource_level=resource_level,
                last_seen=published_at,
                object_marking_refs=marking_id,
                created_by_ref=author_org_id,
            )
            stix_objects.append(intrusion_set)

            # Create relationships
            relationship_campaign_intrusion = self._create_relationship(
                "attributed-to",
                campaign.id,
                intrusion_set.id,
                published_at,
                marking_id,
                author_org_id,
            )
            stix_objects.append(relationship_campaign_intrusion)

            for identity in identities:
                relationship_intrusion_identity = self._create_relationship(
                    "targets",
                    intrusion_set.id,
                    identity.id,
                    published_at,
                    marking_id,
                    author_org_id,
                )
                stix_objects.append(relationship_intrusion_identity)

            for location in locations:
                relationship_intrusion_location = self._create_relationship(
                    "targets",
                    intrusion_set.id,
                    location.id,
                    published_at,
                    marking_id,
                    author_org_id,
                )
                stix_objects.append(relationship_intrusion_location)

            for industry in industries:
                relationship_intrusion_industry = self._create_relationship(
                    "targets",
                    intrusion_set.id,
                    industry.id,
                    published_at,
                    marking_id,
                    author_org_id,
                )
                stix_objects.append(relationship_intrusion_industry)

        # Send bundle to OpenCTI
        if stix_objects:
            try:
                bundle = stix2.Bundle(
                    objects=stix_objects, allow_custom=True
                ).serialize()
                self.helper.send_stix2_bundle(bundle, update=True, work_id=work_id)
                self.helper.connector_logger.info(
                    f"Successfully processed {len(stix_objects)} STIX objects from CybelAngel."
                )
            except Exception as e:
                self.helper.connector_logger.error(f"Error creating STIX bundle: {e}")

    def process_data(self):
        """
        Main data processing method that manages synchronization with CybelAngel APIs.
        It initiates a work session, retrieves the last run state, processes new data,
        and updates the state in OpenCTI.

        """

        try:
            self.helper.connector_logger.info("Synchronizing with CybelAngel APIs...")
            timestamp = int(time.time())
            now = datetime.fromtimestamp(timestamp, timezone.utc)
            friendly_name = "CybelAngel run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            last_run = current_state.get("last_run") if current_state else None
            self.helper.connector_logger.info(
                "Get Elements since " + last_run
                if last_run
                else "No previous run found"
            )

            self.opencti_bundle(work_id, last_run)
            self.helper.set_state({"last_run": now.astimezone().isoformat()})
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            error_message = f"Unexpected error during synchronization: {str(e)}"
            self.helper.api.work.report_expectation(
                work_id=work_id,
                error={"error": error_message, "source": "CybelAngel Connector"},
            )

            self.helper.connector_logger.error(str(e))

    def run(self):
        """
        Main execution loop for the connector. Determines whether to run once or continuously
        based on the configuration, and triggers the data processing accordingly.

        """
        try:

            self.helper.connector_logger.info("Fetching CybelAngel data ...")
            self.load_marking_definition()
            get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
            if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
                self.process_data()
                self.helper.force_ping()
            else:
                while True:
                    self.process_data()
                    time.sleep(int(self.cybelangel_interval) * 60 * 60)
            pass
        except Exception as e:
            self.helper.connector_logger.error(f"Error in CybelAngel connector: {e}")
            raise


if __name__ == "__main__":
    try:
        cybelAngelConnector = CybelAngel()
        cybelAngelConnector.run()
    except Exception as e:
        print(f"Error running CybelAngel connector: {e}")
        time.sleep(10)
        sys.exit(0)
