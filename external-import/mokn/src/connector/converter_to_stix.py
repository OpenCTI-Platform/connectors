"""STIX data processing for MokN Connector."""

import traceback
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import stix2
from connectors_sdk.models import IPV4Address, OrganizationAuthor, TLPMarking
from mokn.utils import LoginAttemptStatus
from pycti import (
    Incident,
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    StixSightingRelationship,
)

# Threat Levels
THREAT_LEVEL_HIGH = "HIGH"
THREAT_LEVEL_MEDIUM = "MEDIUM"

# STIX Configuration
INDICATOR_VALID_DAYS = 7
INDICATOR_TYPES = ["malicious-activity", "anomalous-activity"]
OBSERVABLE_TYPE_IPV4 = "IPv4-Addr"

# Status groups
STATUS_VALID_CREDENTIALS_LIST = [LoginAttemptStatus.VALID.value]
STATUS_USER_EXISTS_LIST = [
    LoginAttemptStatus.INVALID.value,
    LoginAttemptStatus.VALID.value,
    LoginAttemptStatus.COULD_LOCK.value,
    LoginAttemptStatus.LOCKED_ACCOUNT.value,
]


class ConverterToStix:
    """Handles STIX object creation and management."""

    def __init__(self, helper: OpenCTIConnectorHelper, config: Any) -> None:
        """
        Initialize the STIX converter.
        :param helper: OpenCTI connector helper.
        :param config: Connector settings.
        """
        self.helper = helper
        self.config = config
        self.author_model = OrganizationAuthor(name="MokN")
        self.tlp_marking_model = TLPMarking(level=self.config.mokn.tlp_level.lower())
        self.author = self.author_model.to_stix2_object()
        self.tlp_marking = self.tlp_marking_model.to_stix2_object()

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse a timestamp string to a datetime.
        :param timestamp_str: Timestamp string.
        :return: Parsed datetime.
        """
        try:
            if "T" in timestamp_str and ("Z" in timestamp_str or "+" in timestamp_str):
                return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            if "T" in timestamp_str:
                return datetime.fromisoformat(timestamp_str)
            return datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError):
            self.helper.connector_logger.warning(
                "Could not parse timestamp, using current time",
                {"timestamp": timestamp_str},
            )
            return datetime.now()

    def create_ipv4_observable(self, ip: str) -> stix2.IPv4Address:
        """
        Create IPv4 observable for the given IP address.
        :param ip: IPv4 value.
        :return: STIX IPv4 observable.
        """
        observable = IPV4Address(
            value=ip,
            author=self.author_model,
            markings=[self.tlp_marking_model],
        )
        return observable.to_stix2_object()

    def create_indicator(self, login_attempt: Dict[str, Any]) -> stix2.Indicator:
        """
        Create indicator for a HIGH threat login attempt.
        :param login_attempt: Login attempt payload.
        :return: STIX indicator.
        """
        ip = self._get_ip_from_attempt(login_attempt)
        valid_from = self._get_timestamp_from_attempt(login_attempt)
        valid_until = valid_from + timedelta(days=INDICATOR_VALID_DAYS)
        pattern = f"[ipv4-addr:value = '{ip}']"
        labels = self._build_labels_from_login_attempt(login_attempt)

        # Score is 100 if valid credentials, otherwise 80
        score = 100 if self._has_valid_credentials(login_attempt) else 80

        return stix2.Indicator(
            id=Indicator.generate_id(pattern=pattern),
            name=ip,
            pattern=pattern,
            pattern_type="stix",
            valid_from=valid_from,
            valid_until=valid_until,
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_labels": labels,
                "x_opencti_main_observable_type": OBSERVABLE_TYPE_IPV4,
                "x_opencti_indicator_types": INDICATOR_TYPES,
                "x_opencti_indicator_confidence": 80,
                "x_opencti_score": score,
            },
            object_marking_refs=[self.tlp_marking["id"]],
        )

    def create_sighting(
        self, indicator: stix2.Indicator, login_attempt: Dict[str, Any]
    ) -> stix2.Sighting:
        """
        Create sighting for an indicator.
        :param indicator: STIX indicator.
        :param login_attempt: Login attempt payload.
        :return: STIX sighting.
        """
        observed_time = self._get_timestamp_from_attempt(login_attempt)

        return stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                indicator.id, self.author["id"], observed_time, observed_time
            ),
            sighting_of_ref=indicator.id,
            where_sighted_refs=[self.author["id"]],
            first_seen=observed_time,
            last_seen=observed_time,
            count=1,
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
            object_marking_refs=[self.tlp_marking["id"]],
        )

    def create_indicator_observable_relationship(
        self, indicator: stix2.Indicator, observable: Any
    ) -> stix2.Relationship:
        """
        Create a 'based-on' relationship between indicator and observable.
        :param indicator: STIX indicator.
        :param observable: STIX observable.
        :return: STIX relationship.
        """
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on", indicator.id, observable.id
            ),
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=observable.id,
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
            object_marking_refs=[self.tlp_marking["id"]],
        )

    def create_incident_observable_relationship(
        self, incident: stix2.Incident, observable: Any
    ) -> stix2.Relationship:
        """
        Create a 'related-to' relationship between incident and observable.
        :param incident: STIX incident.
        :param observable: STIX observable.
        :return: STIX relationship.
        """
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", incident.id, observable.id
            ),
            relationship_type="related-to",
            source_ref=incident.id,
            target_ref=observable.id,
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
            object_marking_refs=[self.tlp_marking["id"]],
        )

    def _get_ip_from_attempt(self, login_attempt: Dict[str, Any]) -> str:
        """
        Extract IP address from a login attempt.
        :param login_attempt: Login attempt payload.
        :return: IP address.
        """
        ip = login_attempt.get("ip")
        if not ip:
            raise ValueError("IP address is required")
        return ip

    def _get_timestamp_from_attempt(self, login_attempt: Dict[str, Any]) -> datetime:
        """
        Extract and parse timestamp from a login attempt.
        :param login_attempt: Login attempt payload.
        :return: Parsed datetime.
        """
        date_str = login_attempt.get("date", datetime.now().isoformat())
        return self._parse_timestamp(date_str)

    def _build_labels_from_login_attempt(
        self, login_attempt: Dict[str, Any]
    ) -> List[str]:
        """
        Build labels from a login attempt.
        :param login_attempt: Login attempt payload.
        :return: List of labels.
        """
        labels = []

        threat_level = login_attempt.get("threat_level", "").upper()
        if threat_level == THREAT_LEVEL_HIGH:
            labels.append("mokn:high")
        elif threat_level == THREAT_LEVEL_MEDIUM:
            labels.append("mokn:medium")

        # Add valid credentials label if status is VALID
        if self._has_valid_credentials(login_attempt):
            labels.append("mokn:valid_credentials")

        return labels

    def process_login_attempt(  # pylint: disable=too-many-branches,too-many-statements,broad-exception-caught
        self, login_attempt: Dict[str, Any]
    ) -> List[Any]:
        """
        Process a single login attempt and return STIX objects.
        :param login_attempt: Login attempt payload.
        :return: List of STIX objects.
        """
        if not isinstance(login_attempt, dict) or "ip" not in login_attempt:
            return []

        stix_objects = []
        ip = login_attempt.get("ip")
        indicator = None
        ip_observable = None
        username_obs = None

        try:
            # Handle HIGH threat - create Indicator + Observable + Sighting + Relationships
            if self._is_high_threat(login_attempt):
                try:
                    # Create the IPv4 observable
                    ip_observable = self.create_ipv4_observable(ip)
                    indicator = self.create_indicator(login_attempt)
                    sighting = self.create_sighting(indicator, login_attempt)
                    relationship = self.create_indicator_observable_relationship(
                        indicator, ip_observable
                    )
                    # Add objects in correct order: observable, indicator, relationship, sighting
                    stix_objects.append(ip_observable)
                    stix_objects.append(indicator)
                    stix_objects.append(relationship)
                    stix_objects.append(sighting)
                except (ValueError, TypeError, KeyError) as e:
                    self.helper.connector_logger.error(
                        "Error creating Indicator/Sighting",
                        {"ip": ip, "error": str(e), "type": type(e).__name__},
                    )
                    self.helper.connector_logger.error(traceback.format_exc())

            # Handle MEDIUM threat - create only IP Observable
            elif self._is_medium_threat(login_attempt):
                try:
                    ip_observable = self.create_ipv4_observable(ip)
                    stix_objects.append(ip_observable)
                except (ValueError, TypeError, KeyError) as e:
                    self.helper.connector_logger.error(
                        "Error creating IP observable for MEDIUM threat",
                        {"ip": ip, "error": str(e), "type": type(e).__name__},
                    )
                    self.helper.connector_logger.error(traceback.format_exc())

            # Create username observable for HIGH or MEDIUM if user exists
            if (
                self._is_high_threat(login_attempt)
                or self._is_medium_threat(login_attempt)
            ) and self._user_exists(login_attempt):
                try:
                    username_obs = self._create_username_observable(login_attempt)
                    if username_obs:
                        stix_objects.append(username_obs)
                        # If we have an indicator (HIGH threat only), link the username to it
                        if indicator:
                            username_relationship = (
                                self.create_indicator_observable_relationship(
                                    indicator, username_obs
                                )
                            )
                            stix_objects.append(username_relationship)
                except (ValueError, TypeError, KeyError) as e:
                    self.helper.connector_logger.error(
                        "Error creating username observable",
                        {"error": str(e), "type": type(e).__name__},
                    )

            # Create incident for valid credentials
            if self._has_valid_credentials(login_attempt):
                try:
                    incident = self._create_incident_for_valid_credentials(
                        login_attempt
                    )
                    if incident:
                        stix_objects.append(incident)
                        # Link incident to IP observable
                        incident_ip_rel = self.create_incident_observable_relationship(
                            incident, ip_observable
                        )
                        stix_objects.append(incident_ip_rel)
                        # Link incident to username observable (always exists for valid creds)
                        if username_obs:
                            incident_username_rel = (
                                self.create_incident_observable_relationship(
                                    incident, username_obs
                                )
                            )
                            stix_objects.append(incident_username_rel)
                except (ValueError, TypeError, KeyError) as e:
                    self.helper.connector_logger.error(
                        "Error creating incident for valid credentials",
                        {"error": str(e), "type": type(e).__name__},
                    )
        except (ValueError, TypeError, KeyError) as e:
            self.helper.connector_logger.error(
                "Error processing login attempt",
                {"ip": ip, "error": str(e), "type": type(e).__name__},
            )
            self.helper.connector_logger.error(traceback.format_exc())

        return stix_objects

    def process_attack_data(self, login_attempts: List[Dict[str, Any]]) -> List[Any]:
        """
        Process multiple login attempts and return all STIX objects.
        :param login_attempts: List of login attempts.
        :return: List of STIX objects.
        """
        if not login_attempts:
            return []

        all_stix_objects = []
        processed_count = 0
        high_threat_count = 0
        medium_threat_count = 0

        for login_attempt in login_attempts:
            try:
                stix_objects = self.process_login_attempt(login_attempt)
                if stix_objects:
                    all_stix_objects.extend(stix_objects)
                    processed_count += 1

                    if self._is_high_threat(login_attempt):
                        high_threat_count += 1
                    elif self._is_medium_threat(login_attempt):
                        medium_threat_count += 1
            except (ValueError, TypeError, KeyError) as e:
                ip = login_attempt.get("ip", "unknown")
                self.helper.connector_logger.error(
                    "Error processing login attempt",
                    {"ip": ip, "error": str(e), "type": type(e).__name__},
                )
                continue

        total = len(login_attempts)
        self.helper.connector_logger.info(
            "Login attempts processed",
            {
                "processed": processed_count,
                "total": total,
                "high": high_threat_count,
                "medium": medium_threat_count,
            },
        )

        return all_stix_objects

    def _is_high_threat(self, login_attempt: Dict[str, Any]) -> bool:
        """
        Check if login attempt has HIGH threat level.
        :param login_attempt: Login attempt payload.
        :return: True if HIGH threat.
        """
        threat_level = login_attempt.get("threat_level", "").upper()
        return threat_level == THREAT_LEVEL_HIGH

    def _is_medium_threat(self, login_attempt: Dict[str, Any]) -> bool:
        """
        Check if login attempt has MEDIUM threat level.
        :param login_attempt: Login attempt payload.
        :return: True if MEDIUM threat.
        """
        threat_level = login_attempt.get("threat_level", "").upper()
        return threat_level == THREAT_LEVEL_MEDIUM

    def _has_valid_credentials(self, login_attempt: Dict[str, Any]) -> bool:
        """
        Check if login attempt has valid credentials.
        :param login_attempt: Login attempt payload.
        :return: True if status is VALID.
        """
        status = login_attempt.get("status")
        return status == LoginAttemptStatus.VALID.value

    def _user_exists(self, login_attempt: Dict[str, Any]) -> bool:
        """
        Check if user exists for the login attempt.
        :param login_attempt: Login attempt payload.
        :return: True if user exists.
        """
        status = login_attempt.get("status")
        return status in STATUS_USER_EXISTS_LIST

    def _create_incident_for_valid_credentials(
        self, login_attempt: Dict[str, Any]
    ) -> stix2.Incident:
        """
        Create incident for valid credentials.
        :param login_attempt: Login attempt payload.
        :return: STIX incident.
        """
        ip = login_attempt.get("ip")
        username = login_attempt.get("username", "unknown")
        timestamp = self._get_timestamp_from_attempt(login_attempt)

        incident_name = f"Valid Credentials Compromise - {username}@{ip}"
        description = (
            f"Successful authentication detected on MokN Bait.\n"
            f"Username: {username}\n"
            f"Source IP: {ip}\n"
            f"Timestamp: {timestamp.isoformat()}\n"
            f"This indicates compromised credentials being actively used by an attacker."
        )

        return stix2.Incident(
            id=Incident.generate_id(name=incident_name, created=timestamp),
            name=incident_name,
            description=description,
            created=timestamp,
            custom_properties={
                "created_by_ref": self.author["id"],
                "labels": ["mokn:valid_credentials"],
                "first_seen": timestamp,
                "last_seen": timestamp,
                "severity": "high",
                "incident_type": "compromise",
            },
            object_marking_refs=[self.tlp_marking["id"]],
        )

    def _create_username_observable(
        self, login_attempt: Dict[str, Any]
    ) -> Optional[stix2.UserAccount]:
        """
        Create username observable for existing users.
        :param login_attempt: Login attempt payload.
        :return: STIX user account or None.
        """
        username = login_attempt.get("username")
        if not username:
            return None

        return stix2.UserAccount(
            account_login=username,
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
            object_marking_refs=[self.tlp_marking["id"]],
        )


__all__ = ["ConverterToStix"]
