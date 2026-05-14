"""
RansomFeed Connector
Main connector logic for importing ransomware claims from RansomFeed
"""

import sys
from datetime import datetime, timezone

import stix2
from pycti import OpenCTIConnectorHelper
from ransomfeed.api_client import RansomFeedAPIClient, RansomFeedAPIError
from ransomfeed.config_loader import ConfigLoader
from ransomfeed.converter_to_stix import ConverterToStix


class RansomFeedConnector:
    """
    RansomFeed external import connector

    This connector fetches ransomware claims from the RansomFeed API and converts
    them into STIX 2.1 objects, which are then sent to OpenCTI via RabbitMQ.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigLoader) -> None:
        """
        Initialize the connector

        Args:
            helper: OpenCTI connector helper
            config: Connector configuration
        """
        self.helper = helper
        self.config = config
        self.api_client = RansomFeedAPIClient(config.api_url, helper)
        self.converter = ConverterToStix(helper, config)
        self.work_id = None

    def _process_claim(
        self,
        claim: dict,
        since: "datetime | None" = None,
    ) -> list:
        """
        Process a single ransomware claim and convert it to STIX objects

        Args:
            claim: Dictionary containing claim data from RansomFeed API
            since: When set, claims with ``claimed_at < since`` are skipped
                with a debug log. Used to incrementally process the feed
                even when the upstream API does not honour the ``since``
                query parameter (which is the typical case for RansomFeed —
                the public endpoint always returns the last ~24h of
                claims).
        """
        stix_objects = []

        try:
            # Extract claim data
            claim_id = claim.get("id")
            victim_name = claim.get("victim")
            gang_name = claim.get("gang")
            date_str = claim.get("date")
            country = claim.get("country")
            website = claim.get("website")
            hash_value = claim.get("hash")

            if not victim_name or not gang_name:
                self.helper.connector_logger.warning(
                    "Skipping claim with missing victim or gang", {"claim_id": claim_id}
                )
                return []

            # Parse date - the timestamp is used as input for deterministic
            # ``Report.generate_id`` / relationship ID generators, so we need
            # a stable value. If the date is missing or unparseable, skip the
            # claim instead of falling back to ``datetime.now()`` (which would
            # produce a different ID on every run and create duplicates).
            claim_date = None
            if date_str:
                for fmt in (
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d",
                ):
                    try:
                        claim_date = datetime.strptime(date_str, fmt).replace(
                            tzinfo=timezone.utc
                        )
                        break
                    except ValueError:
                        continue

            if claim_date is None:
                self.helper.connector_logger.warning(
                    "Skipping claim with missing or unparseable date",
                    {"claim_id": claim_id, "date": date_str},
                )
                return []

            # Defense-in-depth client-side filtering. The RansomFeed API
            # currently returns every recent claim (its ``since`` query
            # parameter, if any, is undocumented and appears to be a
            # no-op), so skip claims older than the cursor here.
            if since is not None and claim_date < since:
                self.helper.connector_logger.debug(
                    "Skipping claim older than last_run",
                    {
                        "claim_id": claim_id,
                        "claim_date": claim_date.isoformat(),
                        "last_run": since.isoformat(),
                    },
                )
                return []

            # Create victim organization
            victim = self.converter.create_identity(
                name=victim_name, identity_class="organization"
            )
            stix_objects.append(victim)

            # Create intrusion set (ransomware group)
            intrusion_set = self.converter.create_intrusion_set(
                name=gang_name, description=f"Ransomware group known as {gang_name}"
            )
            stix_objects.append(intrusion_set)

            # Create relationship: intrusion_set targets victim
            relationship = self.converter.create_relationship(
                source_ref=intrusion_set.get("id"),
                target_ref=victim.get("id"),
                relationship_type="targets",
                start_time=claim_date,
                created=claim_date,
            )
            stix_objects.append(relationship)

            # Track object references for the report
            object_refs = [
                victim.get("id"),
                intrusion_set.get("id"),
                relationship.get("id"),
            ]

            # Add location if country is provided
            if country:
                location = self.converter.create_location(country)
                stix_objects.append(location)

                # Victim located at country
                victim_location_rel = self.converter.create_relationship(
                    source_ref=victim.get("id"),
                    target_ref=location.get("id"),
                    relationship_type="located-at",
                )
                stix_objects.append(victim_location_rel)

                # Intrusion set targets country
                intrusion_location_rel = self.converter.create_relationship(
                    source_ref=intrusion_set.get("id"),
                    target_ref=location.get("id"),
                    relationship_type="targets",
                    start_time=claim_date,
                    created=claim_date,
                )
                stix_objects.append(intrusion_location_rel)

                object_refs.extend(
                    [
                        location.get("id"),
                        victim_location_rel.get("id"),
                        intrusion_location_rel.get("id"),
                    ]
                )

            # Add domain if website is provided
            if website:
                try:
                    # Extract domain from URL
                    from urllib.parse import urlparse

                    parsed = urlparse(
                        website if website.startswith("http") else f"http://{website}"
                    )
                    domain_name = parsed.netloc or parsed.path

                    if domain_name:
                        domain = self.converter.create_domain(domain_name)
                        stix_objects.append(domain)

                        # Domain belongs to victim
                        domain_rel = self.converter.create_relationship(
                            source_ref=domain.get("id"),
                            target_ref=victim.get("id"),
                            relationship_type="belongs-to",
                        )
                        stix_objects.append(domain_rel)

                        object_refs.extend([domain.get("id"), domain_rel.get("id")])
                except Exception as e:
                    self.helper.connector_logger.warning(
                        "Error processing website/domain",
                        {"website": website, "error": str(e)},
                    )

            # Add indicator if hash is provided and enabled
            if hash_value and self.config.create_indicators:
                try:
                    indicator = self.converter.create_indicator(
                        pattern=f"[file:hashes.'SHA-256' = '{hash_value}']",
                        name=f"Ransomware sample related to {victim_name}",
                        description=f"Hash of ransomware sample from {gang_name} attack on {victim_name}",
                    )
                    stix_objects.append(indicator)
                    object_refs.append(indicator.get("id"))
                except Exception as e:
                    self.helper.connector_logger.warning(
                        "Error creating indicator",
                        {"hash": hash_value, "error": str(e)},
                    )

            # Create external references
            external_refs = []
            if website:
                external_refs.append(
                    stix2.ExternalReference(
                        source_name="RansomFeed",
                        url=website,
                        description=f"Victim website for {victim_name}",
                    )
                )

            # Create report
            report_name = f"{gang_name} has published a new victim: {victim_name}"
            report_description = (
                f"Ransomware attack by {gang_name} against {victim_name}"
            )
            if date_str:
                report_description += f" discovered on {date_str}"

            report = self.converter.create_report(
                name=report_name,
                description=report_description,
                published=claim_date,
                object_refs=object_refs,
                external_references=external_refs if external_refs else None,
            )
            stix_objects.append(report)

            self.helper.connector_logger.info(
                "Successfully processed claim",
                {"claim_id": claim_id, "victim": victim_name, "gang": gang_name},
            )

        except Exception as e:
            self.helper.connector_logger.error(
                "Error processing claim", {"claim": claim, "error": str(e)}
            )
            return []

        return stix_objects

    @staticmethod
    def _parse_last_run(last_run):
        """Return ``last_run`` parsed as a timezone-aware UTC datetime.

        Accepts the canonical ``"%Y-%m-%dT%H:%M:%SZ"`` format produced
        by :meth:`process_message` and any other ISO-8601 string
        ``datetime.fromisoformat`` understands (older state values may
        carry microseconds / an explicit offset). Returns ``None`` on
        empty / invalid input so the caller can treat the first run as
        "no cursor".
        """
        if not last_run:
            return None
        try:
            parsed = datetime.strptime(last_run, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            try:
                parsed = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
            except ValueError:
                return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _collect_intelligence(self, last_run: str = None) -> list:
        """
        Collect intelligence from RansomFeed API

        Args:
            last_run: Optional last run timestamp ("YYYY-MM-DDTHH:MM:SSZ")
                stored by :meth:`process_message`. Used to filter the API
                response client-side and as a best-effort ``since`` query
                parameter for the API.

        Returns:
            List of STIX objects
        """
        stix_objects = []

        # Parse ``last_run`` back into a timezone-aware datetime so the
        # client-side filter in ``_process_claim`` and the API
        # ``since`` parameter use a consistent representation.
        since_dt = self._parse_last_run(last_run)
        api_since = (
            since_dt.strftime("%Y-%m-%d %H:%M:%S") if since_dt is not None else None
        )

        try:
            # Fetch claims from API. The query parameter is best-effort;
            # ``_process_claim`` filters the response client-side too.
            claims = self.api_client.get_recent_claims(since=api_since)

            if not claims:
                self.helper.connector_logger.info("No new claims to process")
                return []

            self.helper.connector_logger.info(
                "Processing claims from RansomFeed",
                {"num_claims": len(claims), "since": api_since},
            )

            # Process each claim
            for claim in claims:
                claim_objects = self._process_claim(claim, since=since_dt)
                stix_objects.extend(claim_objects)

            # Add author and TLP marking definition to objects so the
            # ``cleanup_inconsistent_bundle=True`` worker option does not
            # strip ``object_marking_refs`` / ``created_by_ref`` references.
            if stix_objects:
                stix_objects.append(self.converter.author)
                if self.converter.marking is not None:
                    stix_objects.append(self.converter.marking)

        except RansomFeedAPIError as e:
            self.helper.connector_logger.error(
                "Error fetching data from RansomFeed API", {"error": str(e)}
            )
            raise

        return stix_objects

    def process_message(self) -> None:
        """
        Main process to collect intelligence from RansomFeed
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting RansomFeed connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get current state
            now = datetime.now(timezone.utc)
            current_state = self.helper.get_state()

            last_run = None
            if current_state and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run", {"last_run": last_run}
                )
            else:
                self.helper.connector_logger.info("[CONNECTOR] Connector has never run")

            # Initiate work
            friendly_name = "RansomFeed import"
            self.work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running RansomFeed connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Collect intelligence
            stix_objects = self._collect_intelligence(last_run)

            if stix_objects:
                # Deduplicate objects
                stix_objects = self.helper.stix2_deduplicate_objects(stix_objects)

                # Create and send bundle
                bundle = self.helper.stix2_create_bundle(stix_objects)

                self.helper.connector_logger.info(
                    "Sending STIX bundle to OpenCTI", {"num_objects": len(stix_objects)}
                )

                self.helper.send_stix2_bundle(
                    bundle=bundle,
                    work_id=self.work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Successfully sent STIX objects to OpenCTI",
                    {"num_objects": len(stix_objects)},
                )
            else:
                self.helper.connector_logger.info("No data to send to OpenCTI")

            # Update state. Use a stable, parseable representation
            # (no microseconds, no offset) so the value is unambiguous
            # across runs and matches what ``_parse_last_run`` expects.
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%dT%H:%M:%SZ")

            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}

            self.helper.set_state(current_state)

            message = f"RansomFeed connector successfully run, storing last_run as {current_state_datetime}"
            self.helper.api.work.to_processed(self.work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Error in connector", {"error": str(e)}
            )
            if self.work_id:
                # ``in_error=True`` so the work is marked as failed in
                # the OpenCTI UI instead of being silently reported as
                # successful (matches the pattern used by
                # ``external-import/cvelistv5`` and
                # ``external-import/opencti-stream``).
                self.helper.api.work.to_processed(
                    self.work_id,
                    f"Error: {str(e)}",
                    in_error=True,
                )
        finally:
            self.work_id = None

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
