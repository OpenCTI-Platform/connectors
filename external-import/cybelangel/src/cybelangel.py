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
            config_file_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "config.yml"
            )
            if os.path.isfile(config_file_path):
                with open(config_file_path, encoding="utf-8") as config_file:
                    config = yaml.safe_load(config_file) or {}
            else:
                config = {}

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
                default="info",
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
                default="https://platform.cybelangel.com",
            )
            self.cybelangel_auth_url = get_config_variable(
                "CYBELANGEL_AUTH_URL",
                ["cybelangel", "auth_url"],
                config,
                default="https://auth.cybelangel.com/oauth/token",
            )
            # OAuth2 ``audience`` claim sent during client-credentials
            # exchange. Defaults to the configured CybelAngel API URL so
            # the audience stays consistent with the API host when a
            # custom ``CYBELANGEL_API_URL`` is used (the CybelAngel
            # authorization server validates audience against the API
            # host). Operators can still override it explicitly when the
            # audience deviates from the API base URL.
            self.cybelangel_audience = get_config_variable(
                "CYBELANGEL_AUDIENCE",
                ["cybelangel", "audience"],
                config,
                default=self.cybelangel_api_url.rstrip("/") + "/",
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

            # Scheduler / auto-backpressure (ISO 8601). Default = PT6H, i.e., 6 hours.
            self.duration_period = get_config_variable(
                "CONNECTOR_DURATION_PERIOD",
                ["connector", "duration_period"],
                config,
                default="PT6H",
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
        TLP_MAPPING = {
            "TLP:WHITE": stix2.TLP_WHITE,
            # ``TLP:CLEAR`` is OpenCTI's canonical replacement for the
            # legacy ``TLP:WHITE`` and is not exported as a constant by
            # the ``stix2`` library. We therefore build it as a custom
            # ``MarkingDefinition`` (mirroring the ``TLP:AMBER+STRICT``
            # entry below) so the marking id / label match what OpenCTI
            # ingests and the configured value is preserved as-is —
            # aliasing it to ``stix2.TLP_WHITE`` would silently tag
            # ingested data with the TLP:WHITE marking id.
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

        tlp_value = self.cybelangel_marking.strip().upper()
        if tlp_value in TLP_MAPPING:
            self.cybelangel_marking = TLP_MAPPING[tlp_value]
        else:
            self.helper.connector_logger.warning(
                f"Unsupported TLP marking '{tlp_value}', defaulting to TLP:AMBER+STRICT"
            )
            self.cybelangel_marking = TLP_MAPPING["TLP:AMBER+STRICT"]

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
            :param delay: Delay in seconds between retry attempts.
            :param max_retries: Maximum number of retry attempts.
        """

        auth_data = {
            "client_id": self.cybelangel_client_id,
            "client_secret": self.cybelangel_client_secret,
            "audience": self.cybelangel_audience,
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
                    self.cybelangel_auth_url,
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
                    # Only announce the delay when another attempt will
                    # actually follow - logging "Retrying in N seconds"
                    # on the terminal attempt is misleading and makes
                    # troubleshooting harder.
                    self.helper.connector_logger.info(
                        f"Retrying in {delay} seconds... (Attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(delay)
                else:
                    self.helper.connector_logger.error(
                        f"Authentication failed after {max_retries} attempts, giving up."
                    )

    def create_cybelangel_org(self):
        """
        Creates an identity object for the CybelAngel organization.

        This function generates a STIX 2.1 Identity object representing the CybelAngel organization. The identity includes details such as the name, description, confidence level, identity class, type, and object marking references.

        """
        try:
            identity = stix2.Identity(
                id=Identity.generate_id("CybelAngel", "organization"),
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
        ``False`` otherwise. The caller uses this signal to decide whether
        ``last_run`` should be advanced.
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
        """
        Compute since_date/end_date and build the CybelAngel API parameters.

        Returns ``(since_date, end_date, parameters)``. When the configured
        ``CYBELANGEL_FETCH_PERIOD`` is ``"all"`` and there is no usable
        ``last_run`` cursor, ``since_date`` / ``end_date`` are ``None`` and
        ``parameters`` only carries the sort (``sort_by=claimed_at&sort_order=desc``)
        so the CybelAngel API returns the full history.
        """

        base_sort = "sort_by=claimed_at&sort_order=desc"

        if last_run:
            try:
                since_date = datetime.fromisoformat(last_run).astimezone(timezone.utc)
            except ValueError:
                # ``last_run`` is corrupted or in an unexpected format.
                # Fall back to ``CYBELANGEL_FETCH_PERIOD`` exactly like the
                # "no ``last_run``" branch below, including the ``all``
                # case which means "no date filter".
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

        # No last_run -> we use CYBELANGEL_FETCH_PERIOD.
        return self._fetch_parameters_from_period(base_sort)

    def _fetch_parameters_from_period(self, base_sort):
        """Return ``(since_date, end_date, parameters)`` derived from ``CYBELANGEL_FETCH_PERIOD``.

        ``CYBELANGEL_FETCH_PERIOD`` is either a number of days (``int`` / ``str``)
        or ``"all"`` to mean "no date filter".
        """
        fetch_period = getattr(self, "cybelangel_fetch_period", "all")
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
        """Page through ``claimed-attacks`` and process every record.

        Returns ``True`` when the iteration completes without
        unrecoverable errors *and* every per-attack bundle was sent
        successfully. Returns ``False`` when the connector gives up on
        transient errors **or** when any ``_process_attack`` failed —
        the caller uses the return value to keep ``last_run``
        un-advanced so the next run retries instead of silently
        dropping data.
        """
        skip = 0
        limit = 50
        attempt = 0
        # Track per-attack bundle-send failures. We keep iterating even
        # after a failure (each attack is independent and re-runs are
        # idempotent thanks to deterministic STIX ids), but return
        # ``False`` at the end so the caller does not advance ``last_run``.
        all_succeeded = True

        while True:
            url = (
                f"{self.cybelangel_api_url}"
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

            # The CybelAngel token expires after 1 hour. This block
            # reauthenticates when the token is no longer valid.
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
                attempt = 0  # Reset attempt counter on successful response
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

            # Reset retry counter once we got a successful response.
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
                # Results are sorted by ``claimed_at desc``: once we see one
                # claim older than ``since_date`` every following claim
                # (within this page and on subsequent pages) is older too,
                # so we can stop iterating entirely instead of just skipping.
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
        """Process a single attack and forward the resulting STIX bundle.

        Returns ``True`` when the attack was handled successfully (or
        deliberately skipped because of an unparseable timestamp / a
        cursor cut-off) and ``False`` when bundle serialisation or
        ``send_stix2_bundle`` failed — callers use this signal to keep
        ``last_run`` un-advanced so the run is retried instead of
        silently dropping data.
        """
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

        # ``claimed_at`` is used as the deterministic timestamp for several
        # required STIX fields (``Campaign.created``, ``first_seen``,
        # ``last_seen``, relationship ``created``, ...). A missing or
        # unparseable value would make the bundle invalid and crash the run,
        # so we skip the record with a warning instead.
        if claimed_at is None:
            self.helper.connector_logger.warning(
                "Skipping attack with missing or unparseable claimed_at",
                {"attack_id": attack.get("id"), "claimed_at": claimed_at_raw},
            )
            return True

        # Stop early if attack is before last_run
        if since_date and claimed_at < since_date:
            self.helper.connector_logger.info(
                f"Stopping processing as claimed_at {claimed_at.strftime('%Y-%m-%dT%H:%M:%SZ')} is before "
                f"last_run value {since_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
            return True

        stix_objects = [author_org, self.cybelangel_marking]
        author_org_id = author_org["id"] if author_org else None
        marking_id = [self.cybelangel_marking.id] if self.cybelangel_marking else None

        # Attack fields
        campaign_objective = attack.get("category", "Unknown")
        threat_actors = attack.get("threat_actors", []) or []
        countries = attack.get("countries", []) or []
        industries_list = attack.get("industries", []) or []
        victims = attack.get("victims", []) or []
        domains = attack.get("domains", []) or []

        # Resource level heuristic. STIX 2.1 ``IntrusionSet.resource_level``
        # is an open-vocabulary lowercase enum (e.g. ``individual``, ``team``,
        # ``contest``, ``organization``), so we must use the lowercase values.
        resource_level = (
            "contest" if "ddos" in campaign_objective.lower() else "organization"
        )

        # Actor label used in campaign naming
        final_actor = (
            threat_actors[0]
            if (threat_actors and threat_actors[0])
            else "Unknown actor"
        )
        campaign_date = f" ({claimed_at.date()})"

        # --- Locations (countries) shared across campaigns for this attack
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

        # --- Sectors (industries) shared across campaigns for this attack
        sector_objs = []
        for ind in industries_list:
            if not ind:
                continue
            sector = self._create_identity(ind, "class", marking_id, author_org_id)
            if sector:
                sector_objs.append(sector)
                stix_objects.append(sector)

        # --- Intrusion Sets shared across campaigns for this attack
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

        # --- If no victims at all: keep a generic campaign (backward compatible)
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

            # campaign -> locations
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
            # campaign -> sectors
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
            # campaign -> intrusion sets
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
            # intrusion sets -> locations / sectors
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

            # Create victim identity
            identity = self._create_identity(
                v, "organization", marking_id, author_org_id, victim_domain
            )
            if identity:
                stix_objects.append(identity)

            # Create a dedicated campaign for this victim
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

            # campaign -> victim
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
            # campaign -> locations
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
            # campaign -> sectors
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
            # campaign -> intrusion sets
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

            # intrusion sets -> victim (per-victim, varies with ``identity.id``)
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

        # --- intrusion sets -> locations / sectors are per-attack rather than
        # per-victim. ``StixCoreRelationship.generate_id`` is deterministic
        # on ``(rel_type, source, target)``, so emitting them inside the
        # per-victim loop above used to produce N copies of the same
        # Relationship (one per victim) with identical ids/content — which
        # inflates bundles and can fail STIX validation. They are now
        # emitted once per attack here. (The "no victims" branch above
        # already emitted them once per attack.)
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

        # Send bundle to OpenCTI. Any failure here is propagated to the
        # caller so the pagination loop can keep ``last_run`` un-advanced
        # — otherwise a single failed bundle would silently drop data.
        if stix_objects:
            try:
                bundle = stix2.Bundle(
                    objects=stix_objects, allow_custom=True
                ).serialize()
                # ``update=`` was deprecated in pycti; the worker now always
                # applies the relevant patch semantics.
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

    def process_data(self):
        """Main data processing method.

        Initiates a work, retrieves the previous ``last_run`` from state,
        fetches the new claimed attacks and only advances ``last_run`` when
        :meth:`opencti_bundle` reports a successful run.
        """
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
                # Always store the ``last_run`` cursor in UTC ISO 8601 so the
                # ``start_date`` / ``end_date`` parameters built on the next
                # run are time-zone consistent.
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

    def run(self):
        """
        Run using OpenCTI Scheduler (ISO 8601 duration + auto-backpressure).

        """
        try:
            self.helper.connector_logger.info("Fetching CybelAngel data ...")
            self.load_marking_definition()

            self.helper.schedule_iso(
                message_callback=self.process_data,
                duration_period=self.duration_period,
            )

        except Exception as e:
            self.helper.connector_logger.error(f"Error in CybelAngel connector: {e}")
            raise


if __name__ == "__main__":
    try:
        connector = CybelAngel()
        connector.run()
    except Exception as e:
        # Non-zero exit so container supervisors / CI / restart policies
        # do not mistake a crash for a successful run.
        print(f"Error running CybelAngel connector: {e}")
        time.sleep(10)
        sys.exit(1)
