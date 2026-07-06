import sys
import time
from datetime import datetime, timedelta, timezone

import requests
import stix2
from connector.settings import ConnectorSettings
from pycti import (
    Campaign,
    Identity,
    IntrusionSet,
    Location,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class CybelAngel:
    """Main class for the CybelAngel OpenCTI connector."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        # Resolve audience: use explicit value or fall back to api_url + "/"
        self._audience = (
            self.config.cybelangel.audience
            if self.config.cybelangel.audience is not None
            else self.config.cybelangel.api_url.rstrip("/") + "/"
        )

        # Marking definition is resolved lazily in run() via load_marking_definition()
        self.cybelangel_marking = None

    def load_marking_definition(self):
        """Load or create a STIX MarkingDefinition object based on the configured TLP level."""
        TLP_MAPPING = {
            "TLP:WHITE": stix2.TLP_WHITE,
            "TLP:CLEAR": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:CLEAR",
            ),
            "TLP:GREEN": stix2.TLP_GREEN,
            "TLP:AMBER": stix2.TLP_AMBER,
            "TLP:AMBER+STRICT": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "TLP:AMBER+STRICT"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            ),
            "TLP:RED": stix2.TLP_RED,
        }

        tlp_value = self.config.cybelangel.marking.strip().upper()
        if tlp_value in TLP_MAPPING:
            self.cybelangel_marking = TLP_MAPPING[tlp_value]
        else:
            self.helper.connector_logger.warning(
                f"Unsupported TLP marking '{tlp_value}', defaulting to TLP:AMBER+STRICT"
            )
            self.cybelangel_marking = TLP_MAPPING["TLP:AMBER+STRICT"]

    def authenticate(self, max_retries=3, delay=5):
        """Authenticate with the CybelAngel API using client credentials."""
        auth_data = {
            "client_id": self.config.cybelangel.client_id,
            "client_secret": self.config.cybelangel.client_secret.get_secret_value(),
            "audience": self._audience,
            "grant_type": "client_credentials",
        }

        headers = {
            "Content-Type": "application/json",
            "User-agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 "
            ),
        }
        for attempt in range(1, max_retries + 1):
            self.helper.connector_logger.info(
                f"Attempt {attempt} to authenticate with CybelAngel API"
            )
            try:
                response = requests.post(
                    self.config.cybelangel.auth_url,
                    json=auth_data,
                    headers=headers,
                    timeout=(10, 60),
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
                    f"Error during authentication attempt {attempt}/{max_retries}: {e}"
                )
                if attempt < max_retries:
                    self.helper.connector_logger.info(
                        f"Retrying in {delay} seconds... (Attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(delay)
                else:
                    self.helper.connector_logger.error(
                        f"Authentication failed after {max_retries} attempts, giving up."
                    )

    def create_cybelangel_org(self):
        """Creates an identity object for the CybelAngel organization."""
        try:
            identity = stix2.Identity(
                id=Identity.generate_id("CybelAngel", "organization"),
                spec_version="2.1",
                name="CybelAngel",
                description=(
                    "Cybelangel is a cybersecurity company that specializes in detecting "
                    "and mitigating cyber threats."
                ),
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
        claimed_at,
        marking=None,
        created_by=None,
    ):
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            source_ref=source_id,
            target_ref=target_id,
            created=claimed_at,
            relationship_type=rel_type,
            object_marking_refs=marking,
            created_by_ref=created_by,
        )

    # ----------------------
    # Fetch Data
    # ----------------------
    def opencti_bundle(self, work_id, last_run=None):
        """Authenticate, fetch and ingest claimed attacks.

        Returns ``True`` when the run completes without unrecoverable errors,
        ``False`` otherwise.
        """
        token = self.authenticate()
        if not token:
            self.helper.connector_logger.error(
                "Authentication with CybelAngel failed, aborting this run."
            )
            return False
        self.helper.connector_logger.debug(
            "Token received, proceeding with data fetching."
        )

        cybelangel_org_identity = self.create_cybelangel_org()
        if not cybelangel_org_identity:
            self.helper.connector_logger.error(
                "Could not create the CybelAngel identity, aborting this run."
            )
            return False

        since_date, _end_date, parameters = self._build_fetch_parameters(last_run)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        return self._fetch_and_process_pages(
            headers, parameters, cybelangel_org_identity, work_id, since_date
        )

    def _build_fetch_parameters(self, last_run):
        """Compute since_date/end_date and build the CybelAngel API parameters."""
        base_sort = "sort_by=claimed_at&sort_order=desc"

        if last_run:
            try:
                since_date = datetime.fromisoformat(last_run).astimezone(timezone.utc)
            except ValueError:
                self.helper.connector_logger.warning(
                    "Invalid last_run format, falling back to CYBELANGEL_FETCH_PERIOD",
                    {"last_run": last_run},
                )
                return self._fetch_parameters_from_period(base_sort)
            end_date = datetime.now(timezone.utc)
            parameters = (
                f"{base_sort}"
                f"&start_date={since_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
                f"&end_date={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
            return since_date, end_date, parameters

        return self._fetch_parameters_from_period(base_sort)

    def _fetch_parameters_from_period(self, base_sort):
        """Return ``(since_date, end_date, parameters)`` derived from ``CYBELANGEL_FETCH_PERIOD``."""
        fetch_period = self.config.cybelangel.fetch_period
        if not fetch_period or str(fetch_period).lower() == "all":
            return None, None, base_sort

        try:
            days = int(fetch_period)
        except (TypeError, ValueError):
            self.helper.connector_logger.warning(
                "Invalid CYBELANGEL_FETCH_PERIOD value, falling back to full history",
                {"fetch_period": fetch_period},
            )
            return None, None, base_sort

        since_date = datetime.now(timezone.utc) - timedelta(days=days)
        since_date = since_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = datetime.now(timezone.utc)
        parameters = (
            f"{base_sort}"
            f"&start_date={since_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            f"&end_date={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        return since_date, end_date, parameters

    def _fetch_and_process_pages(
        self, headers, parameters, author_org, work_id, since_date
    ):
        """Page through ``claimed-attacks`` and process every record."""
        skip = 0
        limit = 50
        attempt = 0
        all_succeeded = True

        while True:
            url = (
                f"{self.config.cybelangel.api_url}"
                f"/api/v1/threat-intelligence/claimed-attacks"
                f"?limit={limit}&skip={skip}&{parameters}"
            )
            self.helper.connector_logger.debug(
                f"Fetching data from CybelAngel API: {url}"
            )

            try:
                response = requests.get(url, headers=headers, timeout=(10, 60))
            except requests.exceptions.RequestException as exc:
                attempt += 1
                self.helper.connector_logger.error(
                    f"Network error while fetching CybelAngel data: {exc}. "
                    f"Retrying ({attempt}/3)..."
                )
                if attempt >= 3:
                    self.helper.connector_logger.error(
                        "Failed to fetch data after 3 attempts, aborting this run."
                    )
                    return False
                time.sleep(5)
                continue

            if response.status_code == 401 and attempt < 3:
                attempt += 1
                self.helper.connector_logger.info(
                    f"Token expired, re-authenticating. Attempt {attempt}..."
                )
                token = self.authenticate()
                if not token:
                    self.helper.connector_logger.error(
                        "Re-authentication failed, aborting this run."
                    )
                    return False
                headers["Authorization"] = f"Bearer {token}"
                self.helper.connector_logger.info(
                    "Re-authentication successful, retrying data fetch."
                )
                attempt = 0
                continue
            if response.status_code != 200:
                self.helper.connector_logger.error(
                    f"Failed to fetch data from CybelAngel: {response.status_code}. "
                    f"Response: {response.text}. Retrying..."
                )
                attempt += 1
                if attempt >= 3:
                    self.helper.connector_logger.error(
                        "Failed to fetch data after 3 attempts, aborting this run."
                    )
                    return False
                time.sleep(5)
                continue

            attempt = 0

            attacks = response.json().get("claimed_attacks", [])
            if not attacks:
                self.helper.connector_logger.info(
                    "No more attacks found, stopping processing."
                )
                return all_succeeded

            self.helper.connector_logger.info(
                f"Processing {len(attacks)} attacks - skip {skip} with limit {limit}"
            )

            for attack in attacks:
                if self._is_attack_too_old(attack, since_date):
                    self.helper.connector_logger.info(
                        "Reached claims older than last_run, stopping pagination."
                    )
                    return all_succeeded
                if not self._process_attack(attack, since_date, author_org, work_id):
                    all_succeeded = False

            skip += limit

    @staticmethod
    def _is_attack_too_old(attack: dict, since_date) -> bool:
        if since_date is None:
            return False
        claimed_at_raw = attack.get("claimed_at")
        if not claimed_at_raw:
            return False
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                claimed_at = datetime.strptime(claimed_at_raw, fmt).replace(
                    tzinfo=timezone.utc
                )
                break
            except ValueError:
                continue
        else:
            return False
        return claimed_at < since_date

    # ----------------------
    # Parse & Ingest Data
    # ----------------------
    def _process_attack(self, attack, since_date, author_org, work_id) -> bool:
        """Process a single attack and forward the resulting STIX bundle."""
        claimed_at_raw = attack.get("claimed_at")
        claimed_at = None
        if claimed_at_raw:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    claimed_at = datetime.strptime(claimed_at_raw, fmt).replace(
                        tzinfo=timezone.utc
                    )
                    break
                except ValueError:
                    continue

        if claimed_at is None:
            self.helper.connector_logger.warning(
                "Skipping attack with missing or unparseable claimed_at",
                {"attack_id": attack.get("id"), "claimed_at": claimed_at_raw},
            )
            return True

        if since_date and claimed_at < since_date:
            self.helper.connector_logger.info(
                f"Stopping processing as claimed_at {claimed_at.strftime('%Y-%m-%dT%H:%M:%SZ')} is before "
                f"last_run value {since_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
            return True

        stix_objects = [author_org, self.cybelangel_marking]
        author_org_id = author_org["id"] if author_org else None
        marking_id = [self.cybelangel_marking.id] if self.cybelangel_marking else None

        campaign_objective = attack.get("category", "Unknown")
        threat_actors = attack.get("threat_actors", []) or []
        countries = attack.get("countries", []) or []
        industries_list = attack.get("industries", []) or []
        victims = attack.get("victims", []) or []
        domains = attack.get("domains", []) or []

        resource_level = (
            "contest" if "ddos" in campaign_objective.lower() else "organization"
        )

        final_actor = (
            threat_actors[0]
            if (threat_actors and threat_actors[0])
            else "Unknown actor"
        )
        campaign_date = f" ({claimed_at.date()})"

        # --- Locations (countries)
        locations = []
        for country in countries:
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

        # --- Sectors (industries)
        sector_objs = []
        for ind in industries_list:
            if not ind:
                continue
            sector = self._create_identity(ind, "class", marking_id, author_org_id)
            if sector:
                sector_objs.append(sector)
                stix_objects.append(sector)

        # --- Intrusion Sets
        intrusion_sets = []
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
                last_seen=claimed_at,
                object_marking_refs=marking_id,
                created_by_ref=author_org_id,
            )
            intrusion_sets.append(intrusion_set)
            stix_objects.append(intrusion_set)

        # --- Build victim-domain pairing
        victim_domain_pairs = []
        if victims and domains and len(domains) == len(victims):
            victim_domain_pairs = list(zip(victims, domains))
        elif victims:
            victim_domain_pairs = [(v, None) for v in victims]

        # --- If no victims at all: keep a generic campaign
        if not victim_domain_pairs and not victims:
            campaign_name = f"{campaign_objective.capitalize()} campaign by {final_actor} - {campaign_date}".rstrip(
                " - "
            )
            campaign_description = f"{campaign_objective.capitalize()} campaign by {final_actor} with no specific target"
            campaign = stix2.Campaign(
                id=Campaign.generate_id(campaign_name),
                name=campaign_name,
                description=campaign_description,
                created=claimed_at,
                first_seen=claimed_at,
                last_seen=claimed_at,
                objective=campaign_objective,
                object_marking_refs=marking_id,
                created_by_ref=author_org_id,
            )
            stix_objects.append(campaign)

            for location in locations:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        location.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            for sector in sector_objs:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        sector.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            for iset in intrusion_sets:
                stix_objects.append(
                    self._create_relationship(
                        "attributed-to",
                        campaign.id,
                        iset.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            for iset in intrusion_sets:
                for location in locations:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            location.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )
                for sector in sector_objs:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            sector.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )

        # --- One campaign per victim
        for victim_name, victim_domain in victim_domain_pairs:
            if not victim_name:
                continue
            v = victim_name if len(victim_name) >= 2 else (victim_name + " ")

            identity = self._create_identity(
                v, "organization", marking_id, author_org_id, victim_domain
            )
            if identity:
                stix_objects.append(identity)

            campaign_name = f"{final_actor} targets {v}"
            campaign_description = f"{campaign_objective.capitalize()} campaign by {final_actor} targeting {v}"
            campaign = stix2.Campaign(
                id=Campaign.generate_id(campaign_name),
                name=campaign_name,
                description=campaign_description,
                created=claimed_at,
                first_seen=claimed_at,
                last_seen=claimed_at,
                objective=campaign_objective,
                object_marking_refs=marking_id,
                created_by_ref=author_org_id,
            )
            stix_objects.append(campaign)

            if identity:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        identity.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            for location in locations:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        location.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            for sector in sector_objs:
                stix_objects.append(
                    self._create_relationship(
                        "targets",
                        campaign.id,
                        sector.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )
            for iset in intrusion_sets:
                stix_objects.append(
                    self._create_relationship(
                        "attributed-to",
                        campaign.id,
                        iset.id,
                        claimed_at,
                        marking_id,
                        author_org_id,
                    )
                )

            for iset in intrusion_sets:
                if identity:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            identity.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )

        # --- intrusion sets -> locations / sectors (per-attack, not per-victim)
        if victim_domain_pairs:
            for iset in intrusion_sets:
                for location in locations:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            location.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )
                for sector in sector_objs:
                    stix_objects.append(
                        self._create_relationship(
                            "targets",
                            iset.id,
                            sector.id,
                            claimed_at,
                            marking_id,
                            author_org_id,
                        )
                    )

        if stix_objects:
            try:
                bundle = stix2.Bundle(
                    objects=stix_objects, allow_custom=True
                ).serialize()
                self.helper.send_stix2_bundle(bundle, work_id=work_id)
                self.helper.connector_logger.info(
                    f"Successfully processed {len(stix_objects)} STIX objects from CybelAngel."
                )
            except Exception as e:
                self.helper.connector_logger.error(
                    "Error sending STIX bundle to OpenCTI; last_run will NOT "
                    f"be advanced. attack_id={attack.get('id')!r} error={e}"
                )
                return False
        return True

    def process_message(self) -> None:
        """Connector main process to collect intelligence."""
        work_id = None
        try:
            self.helper.connector_logger.info("Synchronizing with CybelAngel APIs...")
            now = datetime.now(timezone.utc)
            friendly_name = f"CybelAngel run @ {now.strftime('%Y-%m-%d %H:%M:%S')} UTC"
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state() or {}
            last_run = current_state.get("last_run")
            self.helper.connector_logger.info(
                f"Get elements since {last_run}"
                if last_run
                else "No previous run found"
            )

            success = self.opencti_bundle(work_id, last_run)

            if success:
                self.helper.set_state({"last_run": now.isoformat()})
                message = "End of synchronization"
                self.helper.api.work.to_processed(work_id, message)
                self.helper.connector_logger.info(message)
            else:
                message = (
                    "CybelAngel run aborted before completion; last_run not advanced"
                )
                self.helper.api.work.to_processed(work_id, message, in_error=True)
                self.helper.connector_logger.warning(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            error_message = f"Unexpected error during synchronization: {str(e)}"
            self.helper.connector_logger.error(error_message)
            if work_id is not None:
                self.helper.api.work.report_expectation(
                    work_id=work_id,
                    error={
                        "error": error_message,
                        "source": "CybelAngel Connector",
                    },
                )
                self.helper.api.work.to_processed(work_id, error_message, in_error=True)

    def run(self) -> None:
        """Run using OpenCTI Scheduler (ISO 8601 duration + auto-backpressure)."""
        self.helper.connector_logger.info("Fetching CybelAngel data ...")
        self.load_marking_definition()
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
