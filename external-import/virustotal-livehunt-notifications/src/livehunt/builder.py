"""Livehunt builder module."""

import datetime
import io
import ipaddress
import logging
import re
from typing import List, Optional

import magic
import plyara
import plyara.utils
import stix2
import vt
from pycti import Incident, Indicator, OpenCTIConnectorHelper, StixCoreRelationship

logging.getLogger("plyara").setLevel(logging.ERROR)


def _escape_stix_pattern_value(value: str) -> str:
    """Escape backslashes and single quotes for use inside a STIX pattern.

    STIX patterns wrap string values in single quotes and use ``\\`` as the
    escape character. Without escaping, an IOC containing either character
    produces a malformed pattern AND a mismatched deterministic indicator
    id, which silently drops the indicator on import.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


# Conservative RFC-1035 / RFC-1123 style domain check. We deliberately do
# NOT perform any DNS resolution here: a valid C2 domain may be NXDOMAIN
# right now, blocked by the connector's network policy, or only resolve
# AAAA, and we still want to ingest it as an IOC. The previous live
# ``dns.google`` lookup also added up to 5 s per host of latency.
#
# Every label MUST start and end with an alphanumeric character — RFC 1123
# explicitly disallows leading or trailing hyphens **on every label**, not
# only the first one. The ``_LABEL`` building block encodes that:
#
#   * ``[a-zA-Z0-9]`` — first char must be alphanumeric (no leading ``-``);
#   * ``(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?`` — optional middle + trailing
#     run, but if present the trailing char MUST be alphanumeric (no
#     trailing ``-``). The ``?`` makes single-char labels (e.g. ``a.b.c``,
#     ``1.example.com``) still valid.
#
# The previous regex only had a ``(?!-)`` lookahead on the first label,
# so values like ``a.-b.com`` / ``a.b-.com`` slipped through despite
# the comment claiming RFC-style validation.
_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_DOMAIN_REGEX = re.compile(
    rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*\.[a-zA-Z]{{2,63}}$"
)


class LivehuntBuilder:
    """Virustotal Livehunt builder."""

    _SOURCE = "hunting_notification"

    def __init__(
        self,
        client: vt.Client,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        tlp_marking: stix2.MarkingDefinition,
        tag: str | None,
        create_alert: bool,
        max_age_days: int,
        create_file: bool,
        upload_artifact: bool,
        create_yara_rule: bool,
        delete_notification: bool,
        extensions: list[str],
        min_file_size: int,
        max_file_size: int,
        min_positives: int,
        alert_prefix: str,
        av_list: list[str],
        yara_label_prefix: str,
        livehunt_label_prefix: str,
        livehunt_tag_prefix: str,
        enable_label_enrichment: bool,
        *,
        get_malware_config: bool = False,
        create_file_indicators: bool = False,
        create_domain_name_indicators: bool = False,
        create_ip_indicators: bool = False,
        create_url_indicators: bool = False,
        limit: Optional[int] = None,
    ) -> None:
        """Initialize Virustotal builder."""
        self.client = client
        self.helper = helper
        self.author = author
        self.tlp_marking = tlp_marking
        self._default_bundle = [author, tlp_marking]
        self.bundle = self._default_bundle.copy()
        self.tag = tag
        self.with_alert = create_alert
        self.max_age_days = max_age_days
        self.with_file = create_file
        self.upload_artifact = upload_artifact
        self.with_yara_rule = create_yara_rule
        self.delete_notification = delete_notification
        self.extensions = extensions
        self.min_file_size = min_file_size
        self.max_file_size = max_file_size
        self.min_positives = min_positives
        self.alert_prefix = alert_prefix
        self.av_list = av_list
        self.yara_label_prefix = yara_label_prefix
        self.livehunt_label_prefix = livehunt_label_prefix
        self.livehunt_tag_prefix = livehunt_tag_prefix
        self.enable_label_enrichment = enable_label_enrichment
        self.get_malware_config = get_malware_config
        self.create_file_indicators = create_file_indicators
        self.create_domain_name_indicators = create_domain_name_indicators
        self.create_ip_indicators = create_ip_indicators
        self.create_url_indicators = create_url_indicators
        self.limit = limit

    def process(self, start_date: str, timestamp: int):
        # Work id will only be set and instantiated if there are bundles to send.
        work_id = None
        url = "/ioc_stream"
        filter = f"date:{start_date}+ source_type:hunting_ruleset"
        if self.tag is not None and self.tag != "":
            self.helper.connector_logger.debug(f"Setting up filter with tag {self.tag}")
            filter += f" notification_tag:{self.tag}"

        params = {
            "descriptors_only": "False",
            "filter": filter,
        }
        if self.limit is not None:
            # The VT iterator honours ``limit`` as a server-side cap so a small
            # API quota is respected even when the upstream stream is much
            # bigger than what the connector should process in a single run.
            params["limit"] = str(self.limit)
        self.helper.connector_logger.info(
            f"Url for notifications: {url} / params: {params}"
        )

        files_iterator = self.client.iterator(url, params=params)
        processed = 0

        for vtobj in files_iterator:
            if self.limit is not None and processed >= self.limit:
                self.helper.connector_logger.info(
                    f"Reached configured notifications limit ({self.limit}); "
                    "stopping early."
                )
                break

            if self.delete_notification:
                self.delete_livehunt_notification(vtobj.id)

            if self.upload_artifact:
                if not self.artifact_exists_opencti(vtobj.sha256):
                    self.upload_artifact_opencti(vtobj)

            # If extension filters were set
            if self.extensions:
                # If the extension isn't in the list of extensions
                if not hasattr(vtobj, "type_extension"):
                    continue
                elif vtobj.type_extension not in self.extensions:
                    self.helper.connector_logger.info(
                        f"Extension {vtobj.type_extension} not in filter {self.extensions}."
                    )
                    continue

            # If min positives set and file has fewer detections
            if (
                not hasattr(vtobj, "last_analysis_stats")
                or not self.min_positives
                or vtobj.last_analysis_stats.get("malicious", 0) < self.min_positives
            ):
                self.helper.connector_logger.info("Not enough detections")
                continue

            # If min size was set and file is below that size
            if self.min_file_size and self.min_file_size > int(vtobj.size):
                self.helper.connector_logger.info(
                    f"File too small ({vtobj.size} < {self.min_file_size}"
                )
                continue

            # If max size was set and file is above that size
            if self.max_file_size and self.max_file_size < int(vtobj.size):
                self.helper.connector_logger.info(
                    f"File too big ({vtobj.size} > {self.max_file_size}"
                )
                continue

            if self.max_age_days is not None:
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                time_diff = now_utc - vtobj.first_submission_date
                if time_diff.days >= self.max_age_days:
                    self.helper.connector_logger.info(
                        f"First submission date {vtobj.first_submission_date} is too old (more than {self.max_age_days} days"
                    )
                    continue

            # Create external reference to Virustotal report
            external_reference = self.create_external_reference(
                f"https://www.virustotal.com/gui/file/{vtobj.sha256}",
                "Virustotal Analysis",
            )
            incident_id = None
            file_id = None

            if self.with_alert:
                incident_id = self.create_alert(vtobj, external_reference)

            if self.with_file:
                file_id = self.create_file(vtobj, incident_id)

            if self.with_yara_rule:
                for source in vtobj._context_attributes["sources"]:
                    self.create_rule(
                        source["id"],
                        source["label"],
                        incident_id,
                        file_id,
                    )

            if len(self.bundle) > 0:
                if work_id is None:
                    work_id = self.initiate_work(timestamp)
                self.send_bundle(work_id)

            processed += 1

        self.helper.connector_logger.info(
            f"Processing done for {processed} VirusTotal Livehunt notifications."
        )

        if work_id is not None:
            self.helper.api.work.to_processed(
                work_id, message="Connector's work finished gracefully"
            )

    def artifact_exists_opencti(self, sha256: str) -> bool:
        """
        Determine whether an Artifact already exists in OpenCTI.

        sha256: a str representing the sha256 of the artifact's file contents
        returns: a bool indicating the aforementioned
        """

        response = self.helper.api.stix_cyber_observable.read(
            filters={
                "mode": "and",
                "filters": [{"key": "hashes.SHA-256", "values": [sha256]}],
                "filterGroups": [],
            }
        )

        if response:
            return True
        return False

    def create_alert(self, vtobj, external_reference) -> str:
        """
        Create the alert from the livehunt notifications.

        Parameters
        ----------
        vtobj
            Virustotal object with the notification and its related file.
        external_reference : stix2.ExternalReference
            External reference to the file on VirusTotal.

        Returns
        -------
        str
            Id of the created incident.
        """
        # Create the alert
        name = f"""{self.alert_prefix} {vtobj._context_attributes["hunting_info"]["rule_name"]} file={vtobj.sha256}"""
        incident_id = Incident.generate_id(
            name, vtobj._context_attributes["notification_date"]
        )
        alert = self.helper.api.incident.read(id=incident_id)
        if alert:
            self.helper.connector_logger.info(
                f"Alert {alert['id']} already exists, skipping"
            )
            return None
        incident = stix2.Incident(
            id=incident_id,
            incident_type="alert",
            name=name,
            description=f"Date of the alert on VirusTotal: {datetime.datetime.fromtimestamp(vtobj._context_attributes['notification_date'])}",
            source=self._SOURCE,
            created_by_ref=self.author.id,
            labels=self.retrieve_labels(vtobj),
            external_references=[external_reference],
            allow_custom=True,
            object_marking_refs=[self.tlp_marking],
        )
        self.helper.connector_logger.debug(f"Adding alert: {incident}")
        self.bundle.append(incident)
        return incident["id"]

    def create_external_reference(self, url: str, description: str):
        """
        Create an external reference.

        Used to have a link to the file on VirusTotal.

        Parameters
        ----------
        url : str
            Url for the external reference.
        description : str
            Description fot the external reference.

        Returns
        -------
        stix2.ExternalReference
            The external reference object.
        """
        external_reference = stix2.ExternalReference(
            source_name=self.author.name,
            url=url,
            description=description,
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )
        return external_reference

    def create_file(self, vtobj, incident_id: Optional[str] = None) -> str:
        """
        Create a file and link it to the created incident, if any.

        Parameters
        ----------
        vtobj
            Virustotal object with the notification and its related file.
        incident_id : str, optional
            Id of the incident to be linked to the file using a `related-to` relationship.

        Returns
        -------
        str
            Id of the created file.
        """
        vt_score = None
        try:
            if hasattr(vtobj, "last_analysis_stats"):
                vt_score = self._compute_score(vtobj.last_analysis_stats)
        except ZeroDivisionError as e:
            self.helper.metric.inc("error_count")
            self.helper.connector_logger.error(
                f"Unable to compute score of file, err = {e}"
            )

        external_reference = self.create_external_reference(
            f"https://www.virustotal.com/gui/file/{vtobj.sha256}",
            "Virustotal Analysis",
        )

        ## Add the additional name
        x_opencti_additional_names = []
        for name in vtobj.names:
            if not hasattr(vtobj, "meaningful_name") or name != vtobj.meaningful_name:
                x_opencti_additional_names.append(name)

        ## Build a description using the last analysis data from av
        description = ""
        for av in self.av_list:
            av_result = vtobj.last_analysis_results.get(av, {}).get("result")
            description += f"- **{av}**: {av_result}\n"

        # Add the score to the description
        # if score is not None:
        description += f"\nVirusTotal's score: {vt_score}%.\n"

        # add labels from common tags:
        labels = []
        for tag in vtobj.type_tags:
            labels.append(f"{self.livehunt_tag_prefix}{self._normalize_label(tag)}")
        for tag in vtobj.tags:
            labels.append(f"{self.livehunt_tag_prefix}{self._normalize_label(tag)}")

        file = stix2.File(
            type="file",
            name=f"{vtobj.meaningful_name if hasattr(vtobj, 'meaningful_name') else 'unknown'}",
            description=description,
            hashes={
                "MD5": vtobj.md5,
                "SHA-256": vtobj.sha256,
                "SHA-1": vtobj.sha1,
            },
            size=vtobj.size,
            external_references=[external_reference],
            custom_properties={
                "x_opencti_score": vt_score,
                "created_by_ref": self.author.id,
                "x_opencti_additional_names": x_opencti_additional_names,
            },
            allow_custom=True,
            labels=labels,
            object_marking_refs=[self.tlp_marking],
        )
        self.bundle.append(file)
        # Link to the incident if any.
        if incident_id is not None:
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    incident_id,
                    file["id"],
                ),
                relationship_type="related-to",
                created_by_ref=self.author.id,
                source_ref=incident_id,
                target_ref=file["id"],
                allow_custom=True,
                object_marking_refs=[self.tlp_marking],
            )
            self.bundle.append(relationship)

        # Optionally surface a File Indicator carrying the canonical SHA-256
        # pattern so OpenCTI detection rules pick the verdict up.
        if self.create_file_indicators:
            self._create_file_indicator(vtobj, incident_id, file["id"])

        # Optionally extract C2 infrastructure (domains, IPs, URLs) from the
        # VirusTotal malware configuration analysis and add the resulting
        # observables (and, when configured, indicators) to the bundle.
        if self.get_malware_config:
            self._extract_malware_config(vtobj, incident_id, file["id"])

        return file["id"]

    def _create_file_indicator(
        self,
        vtobj,
        incident_id: Optional[str],
        file_id: str,
    ) -> None:
        """Create a File Indicator for ``vtobj`` and link it back to incident / file."""
        sha256 = vtobj.sha256
        escaped = _escape_stix_pattern_value(sha256)
        pattern = f"[file:hashes.'SHA-256' = '{escaped}']"
        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            created_by_ref=self.author.id,
            name=f"VT Livehunt file {sha256}",
            description=(f"File flagged by VirusTotal Livehunt (SHA-256 {sha256})."),
            pattern=pattern,
            pattern_type="stix",
            valid_from=self.helper.api.stix2.format_date(
                datetime.datetime.now(datetime.timezone.utc)
            ),
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "x_opencti_main_observable_type": "StixFile",
            },
            allow_custom=True,
        )
        self.bundle.append(indicator)
        # based-on between the indicator and the observable, plus a related-to
        # back to the incident so the alert page surfaces the indicator.
        self.bundle.append(
            stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", indicator["id"], file_id
                ),
                relationship_type="based-on",
                created_by_ref=self.author.id,
                source_ref=indicator["id"],
                target_ref=file_id,
                allow_custom=True,
                object_marking_refs=[self.tlp_marking],
            )
        )
        if incident_id is not None:
            self.bundle.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident_id, indicator["id"]
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.author.id,
                    source_ref=incident_id,
                    target_ref=indicator["id"],
                    allow_custom=True,
                    object_marking_refs=[self.tlp_marking],
                )
            )

    def _extract_malware_config(
        self,
        vtobj,
        incident_id: Optional[str],
        file_id: str,
    ) -> None:
        """Extract domain / IP / URL C2 infrastructure from VirusTotal's malware config analysis.

        VirusTotal's ``behaviour_mitre_trees`` endpoint exposes a
        ``malware_configurations`` block on the file object. The exact
        shape depends on the malware family, but each network IOC ends
        up in one of three top-level lists: ``domains``, ``ips``,
        ``urls``. We surface them as STIX observables (and, when the
        ``create_*_indicators`` flags are set, matching Indicators) so
        OpenCTI users can pivot on them without manually re-running the
        analysis.
        """
        try:
            config = self.client.get_object(
                f"/files/{vtobj.sha256}/behaviour_mitre_trees"
            )
        except Exception as exc:
            self.helper.connector_logger.warning(
                f"Failed to fetch malware configuration for {vtobj.sha256}: {exc}"
            )
            return

        configs = getattr(config, "malware_configurations", None) or {}

        for domain in self._unique_strings(configs.get("domains")):
            if not self._is_valid_domain_name(domain):
                self.helper.connector_logger.debug(
                    f"Skipping invalid malware-config domain {domain!r}"
                )
                continue
            observable = stix2.DomainName(
                value=domain,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "x_opencti_created_by_ref": self.author.id,
                },
                allow_custom=True,
            )
            self.bundle.append(observable)
            self._link_malware_config_object(
                observable, incident_id, file_id, "domain-name"
            )
            if self.create_domain_name_indicators:
                self._create_malware_config_indicator(
                    observable, "domain-name", "Domain-Name", incident_id
                )

        for ip in self._unique_strings(configs.get("ips")):
            ip_version = self._ip_version(ip)
            if ip_version is None:
                self.helper.connector_logger.debug(
                    f"Skipping invalid malware-config IP {ip!r}"
                )
                continue
            observable_type = "ipv6-addr" if ip_version == 6 else "ipv4-addr"
            stix_class = stix2.IPv6Address if ip_version == 6 else stix2.IPv4Address
            observable = stix_class(
                value=ip,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "x_opencti_created_by_ref": self.author.id,
                },
                allow_custom=True,
            )
            self.bundle.append(observable)
            self._link_malware_config_object(
                observable, incident_id, file_id, observable_type
            )
            if self.create_ip_indicators:
                octi_type = "IPv6-Addr" if ip_version == 6 else "IPv4-Addr"
                self._create_malware_config_indicator(
                    observable, observable_type, octi_type, incident_id
                )

        for url in self._unique_strings(configs.get("urls")):
            observable = stix2.URL(
                value=url,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "x_opencti_created_by_ref": self.author.id,
                },
                allow_custom=True,
            )
            self.bundle.append(observable)
            self._link_malware_config_object(observable, incident_id, file_id, "url")
            if self.create_url_indicators:
                self._create_malware_config_indicator(
                    observable, "url", "Url", incident_id
                )

    def _link_malware_config_object(
        self,
        observable,
        incident_id: Optional[str],
        file_id: str,
        observable_type: str,
    ) -> None:
        # The observable was contacted by the file => related-to the file,
        # and (when present) to the incident that surfaced the file.
        self.bundle.append(
            stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", file_id, observable.id
                ),
                relationship_type="related-to",
                created_by_ref=self.author.id,
                source_ref=file_id,
                target_ref=observable.id,
                allow_custom=True,
                object_marking_refs=[self.tlp_marking],
            )
        )
        if incident_id is not None:
            self.bundle.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident_id, observable.id
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.author.id,
                    source_ref=incident_id,
                    target_ref=observable.id,
                    allow_custom=True,
                    object_marking_refs=[self.tlp_marking],
                )
            )

    def _create_malware_config_indicator(
        self,
        observable,
        stix_observable_type: str,
        opencti_observable_type: str,
        incident_id: Optional[str],
    ) -> None:
        escaped = _escape_stix_pattern_value(observable.value)
        pattern = f"[{stix_observable_type}:value = '{escaped}']"
        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            created_by_ref=self.author.id,
            name=observable.value,
            description=(
                f"Observable {observable.value} extracted from malware configuration."
            ),
            pattern=pattern,
            pattern_type="stix",
            valid_from=self.helper.api.stix2.format_date(
                datetime.datetime.now(datetime.timezone.utc)
            ),
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "x_opencti_main_observable_type": opencti_observable_type,
            },
            allow_custom=True,
        )
        self.bundle.append(indicator)
        self.bundle.append(
            stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", indicator["id"], observable.id
                ),
                relationship_type="based-on",
                created_by_ref=self.author.id,
                source_ref=indicator["id"],
                target_ref=observable.id,
                allow_custom=True,
                object_marking_refs=[self.tlp_marking],
            )
        )
        if incident_id is not None:
            self.bundle.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", incident_id, indicator["id"]
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.author.id,
                    source_ref=incident_id,
                    target_ref=indicator["id"],
                    allow_custom=True,
                    object_marking_refs=[self.tlp_marking],
                )
            )

    @staticmethod
    def _unique_strings(values) -> list[str]:
        """Return a deduplicated list of trimmed, non-empty string values."""
        if not values:
            return []
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if not isinstance(value, str):
                continue
            value = value.strip()
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    @staticmethod
    def _is_valid_domain_name(value: str) -> bool:
        """Regex-only validation: never block on a live DNS query."""
        return bool(value) and bool(_DOMAIN_REGEX.match(value))

    @staticmethod
    def _ip_version(address: str) -> Optional[int]:
        """Return 4 / 6 for valid IPv4 / IPv6, or None for invalid input."""
        try:
            return ipaddress.ip_address(address).version
        except (ValueError, TypeError):
            return None

    def create_rule(
        self,
        ruleset_id: str,
        rule_name: str,
        incident_id: Optional[str] = None,
        file_id: Optional[str] = None,
    ):
        """
        Get the rule from VirusTotal, parse the yara rules and create the wanted rule.

        A single rule is created, the one having the name matching.
        If an incident or a file has been created, the yara rules will be linked to them.

        Parameters
        ----------
        ruleset_id : str
            Ruleset id of the notification to retrieve.
        rule_name : str
            Name of the rule that matched.
        incident_id : str, optional
            Id of the incident to be linked to the file using a `related-to` relationship.
        file_id : str, optional
            Id of the file to be linked to the file using a `related-to` relationship.
        """
        ruleset = self.client.get_object(f"/intelligence/hunting_rulesets/{ruleset_id}")

        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset.rules)

        for rule in rules:
            if rule["rule_name"] == rule_name:
                self.helper.connector_logger.debug(f"Adding rule name {rule_name}")
                # Default valid_from with current date
                valid_from = self.helper.api.stix2.format_date(
                    datetime.datetime.now(datetime.timezone.utc)
                )
                try:
                    valid_from = self.helper.api.stix2.format_date(
                        next(
                            (
                                i["date"]
                                for i in rule.get("metadata", {})
                                if "date" in i
                            ),
                            None,
                        )
                    )
                except ValueError as e:
                    self.helper.connector_logger.error(
                        f"Date not valid, setting to {valid_from}, err: {e}"
                    )

                indicator = stix2.Indicator(
                    id=Indicator.generate_id(plyara.utils.rebuild_yara_rule(rule)),
                    created_by_ref=self.author.id,
                    name=rule["rule_name"],
                    description=next(
                        (i["date"] for i in rule.get("metadata", {}) if "date" in i),
                        "No description",
                    ),
                    pattern=plyara.utils.rebuild_yara_rule(rule),
                    pattern_type="yara",
                    valid_from=valid_from,
                    custom_properties={
                        "x_opencti_main_observable_type": "StixFile",
                    },
                    object_marking_refs=[self.tlp_marking],
                )
                self.helper.connector_logger.debug(
                    f"[VirusTotal Livehunt Notifications] yara indicator created: {indicator}"
                )
                self.bundle.append(indicator)

                if incident_id is not None:
                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to",
                            incident_id,
                            indicator["id"],
                        ),
                        relationship_type="related-to",
                        created_by_ref=self.author.id,
                        source_ref=incident_id,
                        target_ref=indicator["id"],
                        allow_custom=True,
                        object_marking_refs=[self.tlp_marking],
                    )
                    self.bundle.append(relationship)

                if file_id is not None:
                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to",
                            file_id,
                            indicator["id"],
                        ),
                        relationship_type="related-to",
                        created_by_ref=self.author.id,
                        source_ref=file_id,
                        target_ref=indicator["id"],
                        allow_custom=True,
                        object_marking_refs=[self.tlp_marking],
                    )
                    self.bundle.append(relationship)

    def delete_livehunt_notification(self, notification_id):
        """
        Delete a Livehunt Notification.

        Parameters
        ----------
        notification_id : str
            Io of the notification to delete.
        """
        url = f"/intelligence/hunting_notifications/{notification_id}"
        return self.client.delete(url)

    def initiate_work(self, timestamp: int) -> str:
        now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
        friendly_name = "Virustotal Livehunt Notifications run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.connector_logger.info(
            f"[Virustotal Livehunt Notifications] workid {work_id} initiated"
        )
        return work_id

    def send_bundle(self, work_id: str):
        """
        Send the bundle to OpenCTI.

        After being sent, the bundle is reset.

        Parameters
        ----------
        work_id : str
            Work id to use
        """
        self.helper.metric.inc("record_send", len(self.bundle))
        bundle = stix2.Bundle(objects=self.bundle, allow_custom=True)
        self.helper.connector_logger.debug(f"Sending bundle: {bundle}")
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=work_id)
        # Reset the bundle for the next import.
        self.bundle = self._default_bundle.copy()

    def upload_artifact_opencti(self, vtobj):
        """Upload a file to OpenCTI."""
        file_name = (
            vtobj.meaningful_name if hasattr(vtobj, "meaningful_name") else vtobj.sha256
        )

        # Download the file to a file like object
        file_obj = io.BytesIO()
        self.helper.connector_logger.info(f"Downloading {vtobj.sha256}")
        self.client.download_file(vtobj.sha256, file_obj)
        file_obj.seek(0)
        file_contents = file_obj.read()

        mime_type = magic.from_buffer(file_contents, mime=True)

        kwargs = {
            "file_name": file_name,
            "data": file_contents,
            "mime_type": mime_type,
            "x_opencti_description": "Downloaded from Virustotal Livehunt Notifications.",
            "createdBy": self.author.id,
        }
        return self.helper.api.stix_cyber_observable.upload_artifact(**kwargs)

    def retrieve_labels(self, vtobj) -> List[str]:
        ctx_attributes = vtobj._context_attributes
        labels = [t for t in ctx_attributes["tags"] if t not in {vtobj.id, self.tag}]

        if not self.enable_label_enrichment:
            return labels

        # retrieve the live-hunt related label
        live_hunt_label = ctx_attributes["hunting_info"]["rule_name"]
        if live_hunt_label is not None:
            live_hunt_label = self._normalize_label(live_hunt_label)
            labels = list(filter(lambda s: s != live_hunt_label, labels))
            labels.append(f"{self.livehunt_label_prefix}{live_hunt_label}")

        # retrieve the yara rule names that triggered for this sample
        for source in ctx_attributes["sources"]:
            if source.get("type") != "hunting_ruleset":
                continue

            source_label = self._normalize_label(source["label"])
            labels = list(filter(lambda s: s != source_label, labels))
            labels.append(f"{self.yara_label_prefix}{source_label}")

        return labels

    @staticmethod
    def _normalize_label(label: str) -> str:
        """Based on livehunt's label normalization"""
        return re.sub("[^a-z0-9]", "_", label.lower())

    @staticmethod
    def _compute_score(stats: dict) -> int:
        """
        Compute the score for the observable.

        score = malicious_count / total_count * 100

        Parameters
        ----------
        stats : dict
            Dictionary with counts of each category (e.g. `harmless`, `malicious`, ...)

        Returns
        -------
        int
            Score, in percent, rounded.
        """
        try:
            vt_score = round(
                (
                    stats["malicious"]
                    / (stats["harmless"] + stats["undetected"] + stats["malicious"])
                )
                * 100
            )
        except ZeroDivisionError as e:
            raise ValueError(
                "Cannot compute score. VirusTotal may have no record of the observable"
            ) from e
        return vt_score
