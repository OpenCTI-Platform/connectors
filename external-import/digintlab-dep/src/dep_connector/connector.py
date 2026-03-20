from datetime import UTC, datetime, timedelta

import pycti  # type: ignore[import-untyped]
from pydantic import ValidationError
from stix2 import TLP_AMBER  # type: ignore[import-untyped]
from stix2 import v21 as stix2

from dep_connector.client_api import DepClient
from dep_connector.config_loader import load_config
from dep_connector.converter_to_stix import LeakRecord, PrimaryObject, StixBuilder


class DepConnector:
    def __init__(self) -> None:
        config = load_config()
        self.helper = pycti.OpenCTIConnectorHelper(config)
        label_value = "DigIntLab"
        author_identity = stix2.Identity(
            id=pycti.Identity.generate_id(label_value, identity_class="organization"),
            name=label_value,
            description="We Track and Monitor the Cyber Space",
            contact_information="https://doubleextortion.com/",
            identity_class="organization",
            object_marking_refs=[TLP_AMBER],
        )
        self._current_work_id: str | None = None

        self.interval = pycti.get_config_variable(
            "CONNECTOR_RUN_INTERVAL",
            ["connector", "interval"],
            config,
            default=3600,
            isNumber=True,
        )
        self.lookback_days = pycti.get_config_variable(
            "DEP_LOOKBACK_DAYS",
            ["dep", "lookback_days"],
            config,
            default=7,
            isNumber=True,
        )
        self.overlap_hours = pycti.get_config_variable(
            "DEP_OVERLAP_HOURS",
            ["dep", "overlap_hours"],
            config,
            default=72,
            isNumber=True,
        )
        confidence = pycti.get_config_variable(
            "DEP_CONFIDENCE", ["dep", "confidence"], config, default=70, isNumber=True
        )
        api_key = pycti.get_config_variable("DEP_API_KEY", ["dep", "api_key"], config)
        username = pycti.get_config_variable(
            "DEP_USERNAME", ["dep", "username"], config
        )
        password = pycti.get_config_variable(
            "DEP_PASSWORD", ["dep", "password"], config
        )
        client_id = pycti.get_config_variable(
            "DEP_CLIENT_ID", ["dep", "client_id"], config, default=""
        )
        if not client_id:
            error = "DEP client ID must be provided via configuration"
            raise ValueError(error)
        login_endpoint = pycti.get_config_variable(
            "DEP_LOGIN_ENDPOINT",
            ["dep", "login_endpoint"],
            config,
            default="https://cognito-idp.eu-west-1.amazonaws.com/",
        )
        api_endpoint = pycti.get_config_variable(
            "DEP_API_ENDPOINT",
            ["dep", "api_endpoint"],
            config,
            default="https://api.eu-ep1.doubleextortion.com/v1/dbtr/privlist",
        )
        dataset = pycti.get_config_variable(
            "DEP_DSET",
            ["dep", "dset"],
            config,
            default="ext",
        )
        extended_results = pycti.get_config_variable(
            "DEP_EXTENDED_RESULTS",
            ["dep", "extended_results"],
            config,
            default=True,
        )
        self.enable_site_indicator = pycti.get_config_variable(
            "DEP_ENABLE_SITE_INDICATOR",
            ["dep", "enable_site_indicator"],
            config,
            default=True,
        )
        self.enable_hash_indicator = pycti.get_config_variable(
            "DEP_ENABLE_HASH_INDICATOR",
            ["dep", "enable_hash_indicator"],
            config,
            default=True,
        )
        self.skip_empty_victim = pycti.get_config_variable(
            "DEP_SKIP_EMPTY_VICTIM",
            ["dep", "skip_empty_victim"],
            config,
            default=True,
        )
        self.create_sector_identities = pycti.get_config_variable(
            "DEP_CREATE_SECTOR_IDENTITIES",
            ["dep", "create_sector_identities"],
            config,
            default=True,
        )
        self.create_intrusion_sets = pycti.get_config_variable(
            "DEP_CREATE_INTRUSION_SETS",
            ["dep", "create_intrusion_sets"],
            config,
            default=True,
        )
        self.create_country_locations = pycti.get_config_variable(
            "DEP_CREATE_COUNTRY_LOCATIONS",
            ["dep", "create_country_locations"],
            config,
            default=True,
        )
        primary_object_value = str(
            pycti.get_config_variable(
                "DEP_PRIMARY_OBJECT",
                ["dep", "primary_object"],
                config,
                default=PrimaryObject.REPORT.value,
            )
        ).strip()
        try:
            self.primary_object = PrimaryObject(primary_object_value.lower())
        except ValueError as exc:
            error = (
                "DEP primary object must be one of: report, incident "
                f"(got: {primary_object_value})"
            )
            raise ValueError(error) from exc

        self.client = DepClient(
            login_endpoint=login_endpoint,
            api_endpoint=api_endpoint,
            api_key=api_key,
            username=username,
            password=password,
            client_id=client_id,
            dataset=dataset,
            extended_results=extended_results,
        )
        self.stix = StixBuilder(
            author_identity=author_identity,
            confidence=confidence,
            label_value=label_value,
        )

    def _fetch_data(self, start: datetime, end: datetime) -> list[LeakRecord]:
        raw_items = self.client.fetch_raw(
            start_date=start.strftime("%Y-%m-%d"),
            end_date=end.strftime("%Y-%m-%d"),
        )
        parsed_items: list[LeakRecord] = []
        for raw_item in raw_items:
            try:
                parsed_items.append(LeakRecord(**raw_item))
            except ValidationError as error:
                try:
                    victim_value = raw_item["victim"]
                except KeyError:
                    victim_value = None
                self.helper.log_warning(
                    f"Skipping invalid DEP item for victim {victim_value}: {error}"
                )
        return parsed_items

    def _should_skip_item(self, victim: str | None) -> bool:
        if not self.skip_empty_victim:
            return False
        normalized = (victim or "").strip().lower()
        return normalized in {"", "n/a", "none"}

    def _build_indicators(self, item: LeakRecord) -> list[stix2.Indicator]:
        indicators: list[stix2.Indicator] = []
        if self.enable_site_indicator:
            site_indicator = self.stix.create_site_indicator(item)
            if site_indicator:
                indicators.append(site_indicator)
        if self.enable_hash_indicator:
            hash_indicator = self.stix.create_hash_indicator(item)
            if hash_indicator:
                indicators.append(hash_indicator)
        return indicators

    def _build_indicator_victim_relationships(
        self,
        indicators: list[stix2.Indicator],
        victim: stix2.Identity | None,
    ) -> list[stix2.Relationship]:
        if victim is None:
            return []
        return [
            self.stix.build_relationship("related-to", indicator.id, victim.id)
            for indicator in indicators
        ]

    def _build_cross_entity_relationships(
        self,
        intrusion_set: stix2.IntrusionSet | None,
        sector_identity: stix2.Identity | None,
        country_location: stix2.Location | None,
    ) -> list[stix2._STIXBase21]:
        objects: list[stix2._STIXBase21] = []
        if intrusion_set and sector_identity:
            objects.append(
                self.stix.build_relationship(
                    "targets", intrusion_set.id, sector_identity.id
                )
            )
        if intrusion_set and country_location:
            objects.append(
                self.stix.build_relationship(
                    "targets", intrusion_set.id, country_location.id
                )
            )
        if sector_identity and country_location:
            objects.append(
                self.stix.build_relationship(
                    "related-to", sector_identity.id, country_location.id
                )
            )
        return objects

    def _build_optional_entities(
        self,
        item: LeakRecord,
        victim: stix2.Identity | None,
        incident_id: str | None = None,
    ) -> list[stix2._STIXBase21]:
        objects: list[stix2._STIXBase21] = []
        sector_identity: stix2.Identity | None = None
        if self.create_sector_identities and item.sector and victim:
            sector_identity = self.stix.create_sector_identity(item.sector)
        if sector_identity and victim:
            objects.append(sector_identity)
            objects.append(
                self.stix.build_relationship("part-of", victim.id, sector_identity.id)
            )

        intrusion_set: stix2.IntrusionSet | None = None
        if (
            self.create_intrusion_sets
            and item.actor
            and not self.stix.is_low_quality_actor(item.actor)
        ):
            intrusion_set = self.stix.create_intrusion_set(item.actor)
        if intrusion_set:
            objects.append(intrusion_set)
            if incident_id is not None:
                objects.append(
                    self.stix.build_relationship(
                        "attributed-to", incident_id, intrusion_set.id
                    )
                )

        country_location: stix2.Location | None = None
        if self.create_country_locations and item.country and victim:
            country_location = self.stix.create_country_location(item.country)
        if country_location and victim:
            objects.append(country_location)
            objects.append(
                self.stix.build_relationship(
                    "located-at", victim.id, country_location.id
                )
            )
        objects.extend(
            self._build_cross_entity_relationships(
                intrusion_set, sector_identity, country_location
            )
        )
        return objects

    def _build_content(
        self,
        item: LeakRecord,
        victim: stix2.Identity | None,
        indicators: list[stix2.Indicator],
        incident_id: str | None = None,
    ) -> list[stix2._STIXBase21]:
        content: list[stix2._STIXBase21] = [self.stix.author_identity]
        if victim:
            content.append(victim)
        content.extend(self._build_optional_entities(item, victim, incident_id))
        content.extend(indicators)
        content.extend(self._build_indicator_victim_relationships(indicators, victim))
        return content

    def _send_objects(self, objects: list[stix2._STIXBase21]) -> None:
        if not objects:
            return
        deduped = {obj.id: obj for obj in objects if getattr(obj, "id", None)}
        bundle = stix2.Bundle(objects=list(deduped.values()), allow_custom=True)
        self.helper.send_stix2_bundle(
            bundle.serialize(),
            update=True,
            work_id=self._current_work_id,
            cleanup_inconsistent_bundle=True,
        )

    def _process_item(self, item: LeakRecord) -> None:
        if self._should_skip_item(item.victim):
            self.helper.log_info(
                "Skipping DEP item with empty or placeholder victim value"
            )
            return
        victim = self.stix.create_victim_identity(
            item,
            include_sector_in_description=not self.create_sector_identities,
        )
        indicators = self._build_indicators(item)
        if self.primary_object is PrimaryObject.INCIDENT:
            self._process_item_as_incident(item, victim, indicators)
        else:
            self._process_item_as_report(item, victim, indicators)

    def _process_item_as_incident(
        self,
        item: LeakRecord,
        victim: stix2.Identity | None,
        indicators: list[stix2.Indicator],
    ) -> None:
        incident = self.stix.create_incident(item)
        objects = self._build_content(item, victim, indicators, incident.id)
        objects.append(incident)
        if victim:
            objects.append(
                self.stix.build_relationship("targets", incident.id, victim.id)
            )
        objects.extend(
            self.stix.build_relationship("indicates", indicator.id, incident.id)
            for indicator in indicators
        )
        self._send_objects(objects)

    def _process_item_as_report(
        self,
        item: LeakRecord,
        victim: stix2.Identity | None,
        indicators: list[stix2.Indicator],
    ) -> None:
        content = self._build_content(item, victim, indicators)
        object_refs = [obj.id for obj in content if getattr(obj, "id", None)]
        report = self.stix.create_report(item, object_refs)
        self._send_objects([*content, report])

    def _run_cycle(self) -> None:
        now = datetime.now(UTC)
        start = now - timedelta(days=self.lookback_days)
        state = self.helper.get_state() or {}
        try:
            last_run = state["last_run"]
        except KeyError:
            last_run = None
        if isinstance(last_run, str):
            try:
                start = datetime.fromisoformat(last_run) - timedelta(
                    hours=self.overlap_hours
                )
            except ValueError:
                self.helper.log_warning(
                    f"Ignoring invalid last_run state value: {last_run}"
                )
        elif last_run is not None:
            self.helper.log_warning(
                "Ignoring non-string last_run state value returned by OpenCTI helper"
            )
        end = now

        self.helper.log_info(
            "Fetching DEP data from "
            f"{start.isoformat()} to {end.isoformat()} "
            f"(overlap: {self.overlap_hours}h)"
        )

        self._current_work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"DEP connector - {now.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        )
        try:
            try:
                items = self._fetch_data(start, end)
            except Exception as error:
                self.helper.log_error(f"Failed to fetch DEP data: {error}")
                return

            self.helper.log_info(f"Received {len(items)} entries from DEP API")

            for item in items:
                try:
                    self._process_item(item)
                except Exception as error:
                    self.helper.log_error(
                        f"Failed to process DEP item for victim {item.victim}: {error}"
                    )

            self.helper.log_info("Persisting connector state")
            self.helper.set_state({"last_run": end.isoformat()})
            self.helper.log_info("DEP run completed")
        finally:
            self.helper.api.work.to_processed(
                self._current_work_id,
                f"DEP connector run completed, last_run: {end.isoformat()}",
            )
            self._current_work_id = None

    def run(self) -> None:
        self.helper.log_info("Starting DEP connector")
        self.helper.schedule_iso(
            message_callback=self._run_cycle,
            duration_period=f"PT{self.interval}S",
        )
