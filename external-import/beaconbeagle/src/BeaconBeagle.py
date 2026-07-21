import datetime
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import traceback
import uuid

import requests
import stix2
import yaml
from pycti import (
    AttackPattern,
    CustomObservableText,
    CustomObservableUserAgent,
    Identity,
    Indicator,
    Location,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Tool,
    get_config_variable,
)
from stix2.canonicalization.Canonicalize import canonicalize

# OpenCTI's namespace UUID for deterministic STIX object IDs (matches the
# ``uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")`` namespace used by
# every ``pycti.X.generate_id`` helper). Reused here for SCO types pycti
# does not expose a ``generate_id`` helper for (currently ``Process``)
# so the generated IDs deduplicate against the same objects emitted by
# pycti-using connectors and against each other across runs.
_OPENCTI_NAMESPACE_UUID = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _stix_pattern_escape(value):
    """Escape a string for safe inclusion inside a STIX 2.1 single-quoted literal.

    STIX 2.1 string constants require ``\\`` and ``'`` to be escaped
    inside ``'...'`` literals. Values like URLs or User-Agent strings
    routinely contain those characters; interpolating them raw produces
    invalid patterns and non-deterministic indicator IDs.
    """
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _generate_process_id(command_line):
    """Build a deterministic ``process--`` STIX id from a command line.

    ``stix2.Process`` does not define ``id_contributing_properties`` (the
    STIX 2.1 spec leaves processes inherently transient), so the
    ``stix2`` library otherwise generates a fresh random UUIDv4 on every
    construction. That defeats OpenCTI dedup (the same ``notepad.exe``
    command line keeps being re-created every run) and breaks the
    ``search_id_in_list`` checks below since the id never matches
    across runs.

    Mirror the same UUIDv5(namespace, canonicalize({...})) shape that
    every ``pycti.X.generate_id`` helper uses so the resulting id is
    stable for a given command line and consistent with how the rest
    of the bundle is built.
    """
    data = canonicalize({"command_line": str(command_line)}, utf8=False)
    return "process--" + str(uuid.uuid5(_OPENCTI_NAMESPACE_UUID, data))


class BeaconBeagle:
    """BeaconBeagle connector"""

    def __init__(self):
        """Initializer"""
        # ==============================================================
        # This part is common to all connectors, it loads the config file, and the parameters to local variables
        # ==============================================================
        # Tracks the dedup hash for the *currently-being-processed*
        # payload. Populated by ``beaconbeagle_api_get_list`` and
        # committed to connector state by ``opencti_bundle`` only after
        # a successful ``send_stix2_bundle`` so a build / send failure
        # never silently advances the cursor and drops data on the next
        # run.
        self._pending_payload_hash = None

        # Linked Tool / Attack-Pattern ids are resolved in
        # ``create_stix_bundle`` (only when the corresponding config is set)
        # but read back in ``create_stix_object``. Initialise them here so the
        # read sites are always safe even if ``create_stix_object`` is ever
        # called before ``create_stix_bundle`` (e.g. from a unit test or a
        # future call-order change) instead of raising ``AttributeError``.
        self.beaconbeagle_link_tool_id = None
        self.beaconbeagle_link_ap_id = None

        # Instantiate the connector helper from config.
        # Use a context manager so the file handle is closed deterministically
        # (the previous ``yaml.load(open(...))`` shape leaked the handle on
        # error paths) and ``yaml.safe_load`` so the connector cannot be
        # tricked into instantiating arbitrary Python objects from a
        # malicious / tampered config file.
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config_file_path = config_file_path.replace("\\", "/")
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as config_file:
                config = yaml.safe_load(config_file) or {}
        else:
            config = {}
        self.helper = OpenCTIConnectorHelper(config)

        # Extra config
        # URL: 'https://witha.name/data/last.json'
        self.beaconbeagle_url = get_config_variable(
            "BEACONBEAGLE_URL",
            ["beaconbeagle", "url"],
            config,
            default="https://beaconbeagle.com/api/v1/c2?q=&protocol=&port=&min_endpoints=0&first_after=&first_before=&last_after=&last_before=&sort=firsttime&order=desc",
        )
        #   add_urls: true/false
        self.beaconbeagle_add_urls = get_config_variable(
            "BEACONBEAGLE_ADD_URLS",
            ["beaconbeagle", "add_urls"],
            config,
            default=False,
        )
        #   add_useragent: true/false
        self.beaconbeagle_add_useragent = get_config_variable(
            "BEACONBEAGLE_ADD_USERAGENT",
            ["beaconbeagle", "add_useragent"],
            config,
            default=False,
        )
        #   link_tool: 'CobaltStrike'
        self.beaconbeagle_link_tool = get_config_variable(
            "BEACONBEAGLE_LINK_TOOL",
            ["beaconbeagle", "link_tool"],
            config,
            default="",
        )
        # link_ap: 'T1071 Standard Application Layer Protocol'
        self.beaconbeagle_link_ap = get_config_variable(
            "BEACONBEAGLE_LINK_AP",
            ["beaconbeagle", "link_ap"],
            config,
            default="",
        )
        # link_country: 'true/false''
        self.beaconbeagle_link_country = get_config_variable(
            "BEACONBEAGLE_LINK_COUNTRY",
            ["beaconbeagle", "link_country"],
            config,
            default=False,
        )
        # link_bgpas: 'true/false''
        self.beaconbeagle_link_bgpas = get_config_variable(
            "BEACONBEAGLE_LINK_BGPAS",
            ["beaconbeagle", "link_bgpas"],
            config,
            default=False,
        )

        # search_bgpas: 'true/false''
        self.beaconbeagle_search_bgpas = get_config_variable(
            "BEACONBEAGLE_SEARCH_BGPAS",
            ["beaconbeagle", "search_bgpas"],
            config,
            default=False,
        )

        # link_watermark: ' [CobaltStrikeLicenceWatermark]'
        self.beaconbeagle_link_watermark = get_config_variable(
            "BEACONBEAGLE_LINK_WATERMARK_TXT",
            ["beaconbeagle", "link_watermark"],
            config,
            default="",
        )
        # links_duration: hours used as the fallback indicator-validity
        # window (``valid_from`` → ``valid_until``) when BeaconBeagle does
        # not provide a ``lasttime`` for a given C2 entry. The fallback is
        # wired into ``beaconbeagle_api_get_list`` below — the previous
        # shape loaded this config but never consulted it, so operators
        # changing the value got no effect.
        self.beaconbeagle_links_duration = get_config_variable(
            "BEACONBEAGLE_LINKS_DURATION",
            ["beaconbeagle", "links_duration"],
            config,
            isNumber=True,
            default=24,
        )
        #   interval: 2
        self.beaconbeagle_interval = get_config_variable(
            "BEACONBEAGLE_INTERVAL",
            ["beaconbeagle", "interval"],
            config,
            isNumber=True,
            default=2,
        )
        #   Marking: TLP:GREEN
        self.beaconbeagle_marking = get_config_variable(
            "BEACONBEAGLE_MARKING",
            ["beaconbeagle", "marking_definition"],
            config,
            default="TLP:GREEN",
        )

        self.helper.connector_logger.debug("BeaconBeagle connector initialized.")
        self.helper.connector_logger.debug(
            f"BeaconBeagle url:            {self.beaconbeagle_url}."
        )
        self.helper.connector_logger.debug(
            f"BeaconBeagle link_tool:      {self.beaconbeagle_link_tool}."
        )
        self.helper.connector_logger.debug(
            f"BeaconBeagle add_urls:       {self.beaconbeagle_add_urls}."
        )
        self.helper.connector_logger.debug(
            f"BeaconBeagle add_useragent:  {self.beaconbeagle_add_useragent}."
        )
        self.helper.connector_logger.debug(
            f"BeaconBeagle link_ap:        {self.beaconbeagle_link_ap}."
        )
        self.helper.connector_logger.debug(
            f"BeaconBeagle link_country:   {self.beaconbeagle_link_country}."
        )
        self.helper.connector_logger.debug(
            f"BeaconBeagle link_bgpas:     {self.beaconbeagle_link_bgpas}."
        )
        self.helper.connector_logger.debug(
            f"BeaconBeagle links_duration: {self.beaconbeagle_links_duration}."
        )
        self.helper.connector_logger.debug(
            f"BeaconBeagle interval:       {self.beaconbeagle_interval} hours."
        )
        self.helper.connector_logger.debug(
            f"BeaconBeagle marking:        {self.beaconbeagle_marking}."
        )

    def set_marking(self):
        # Make ``set_marking`` idempotent. ``self.beaconbeagle_marking`` is
        # a configured TLP *string* on entry and the parsed
        # ``stix2.MarkingDefinition`` (or one of the ``stix2.TLP_*``
        # singletons, which are also ``MarkingDefinition`` instances) on
        # exit. Any subsequent invocation — e.g. a future retry loop, a
        # re-entrant ``run()``, or a unit-test fixture exercising the
        # connector more than once — would otherwise hit the ``else``
        # branch (the value is no longer a recognised TLP string) and
        # silently downgrade the operator-configured marking to the
        # ``TLP:AMBER+STRICT`` fallback. Early-return when the marking
        # has already been parsed so the resolved value stays stable
        # across calls.
        if isinstance(self.beaconbeagle_marking, stix2.v21.MarkingDefinition):
            return

        if self.beaconbeagle_marking == "TLP:WHITE":
            marking = stix2.TLP_WHITE
        elif self.beaconbeagle_marking == "TLP:CLEAR":
            # OpenCTI treats ``TLP:CLEAR`` as a distinct marking definition
            # from the legacy ``TLP:WHITE`` (different ``standard_id``);
            # reusing ``stix2.TLP_WHITE`` would silently downgrade
            # ``TLP:CLEAR`` to ``TLP:WHITE`` in the platform.
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:CLEAR",
            )
        elif self.beaconbeagle_marking == "TLP:GREEN":
            marking = stix2.TLP_GREEN
        elif self.beaconbeagle_marking == "TLP:AMBER":
            marking = stix2.TLP_AMBER
        elif self.beaconbeagle_marking == "TLP:AMBER+STRICT":
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )
        elif self.beaconbeagle_marking == "TLP:RED":
            marking = stix2.TLP_RED
        else:
            # Unknown configured value — keep the same custom-marking
            # shape (``definition_type="statement"`` /
            # ``definition={"statement": "custom"}``) as the
            # ``TLP:CLEAR`` / ``TLP:AMBER+STRICT`` branches above so
            # the marking is a well-formed object the platform
            # actually ingests, and fall back to ``TLP:AMBER+STRICT``
            # (the most restrictive sensible default) rather than
            # silently downgrading to ``TLP:WHITE``. The previous
            # ``definition_type="TLP"`` / ``definition={"TLP": ...}``
            # shape diverged from the documented STIX 2.1 marking
            # contract and could be silently ignored by stricter
            # consumers.
            self.helper.connector_logger.warning(
                f"Unknown BEACONBEAGLE_MARKING value {self.beaconbeagle_marking!r}; "
                f"falling back to TLP:AMBER+STRICT."
            )
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )

        self.beaconbeagle_marking = marking

    def beaconbeagle_api_get_list(self) -> list:
        """Return the list of normalised C2 dicts to ingest this cycle.

        Always returns a ``list``. The empty-list return covers every
        "no targets" / recoverable-error path (HTTP non-200, payload
        unchanged since last run, exception during fetch / normalisation),
        so the ``opencti_bundle`` caller has a single contract to test
        against (``if not targeted: ...``) instead of distinguishing
        ``{}`` from ``[]`` from ``None``. The previous shape mixed
        ``return {}`` and ``return [...]`` and relied on ``len(...)``
        coincidentally working for both, which made the function easy
        to misuse from any new call site.
        """
        try:
            headers = {
                "User-Agent": "OpenCTI-BeaconBeagle-Connector/1.1",
                # Standard HTTP header is ``Content-Type``, not
                # ``ContentType``; the previous spelling was silently
                # ignored by servers/proxies that match on the
                # canonical name.
                "Accept": "application/json",
            }
            # Get the full list of IOC from BeaconBeagle.
            # 10 s connect / 60 s read keeps the worker responsive on
            # a hanging endpoint. The previous ``(80000, 80000)``
            # (~22 hours each) effectively disabled the timeout and
            # let a stuck connection block the connector indefinitely.
            self.helper.connector_logger.debug(
                f"Retrieving raw data at : {self.beaconbeagle_url}."
            )
            Raw_Data = requests.get(
                self.beaconbeagle_url,
                headers=headers,
                verify=True,
                timeout=(10, 60),
            )
            self.helper.connector_logger.debug(
                f"We get a response from BeaconBeagle API: {Raw_Data.status_code}."
            )
            if Raw_Data.status_code != 200:
                self.helper.connector_logger.error(
                    f"Error while getting data from BeaconBeagle API: {Raw_Data.status_code}, let's get out of here without data :("
                )
                return []
            _json = Raw_Data.json()
            # Skip processing when the payload has not changed since the
            # previous run. Use the OpenCTI connector state instead of a
            # local JSON dump on disk so the deduplication cursor:
            #   * survives container recreation / rolling restarts
            #     (the previous shape lost the cursor every redeploy);
            #   * works on read-only / ephemeral filesystems;
            #   * stays cheap regardless of payload size (we keep a
            #     32-byte SHA-256 digest rather than re-reading and
            #     re-parsing the entire JSON document on every run).
            payload_hash = hashlib.sha256(
                json.dumps(_json, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            current_state = self.helper.get_state() or {}
            last_payload_hash = current_state.get("last_payload_hash")
            if last_payload_hash == payload_hash:
                self.helper.connector_logger.info(
                    "No new data from BeaconBeagle since last run, skipping processing."
                )
                return []
            if last_payload_hash is None:
                self.helper.connector_logger.info(
                    "First BeaconBeagle run — no previous state to compare against."
                )
            else:
                self.helper.connector_logger.debug(
                    "BeaconBeagle payload changed since last run, processing."
                )
            # Stash the candidate hash on the instance so the caller
            # (``opencti_bundle``) can persist it *after* a successful
            # ``send_stix2_bundle``. Persisting it here would mean a
            # bundle-build / send failure skips ingestion of the same
            # payload on the next run because the dedup cursor already
            # advanced.
            self._pending_payload_hash = payload_hash
            # Process the data
            C2s_json = _json["items"]
            self.helper.connector_logger.info(f"We retrieve: {len(C2s_json)} C2 infos.")

            beaconbeagle_result = []
            for one_C2 in C2s_json:

                # Intialize to None
                C2_ip = None
                C2_key = None
                C2_Firsttime = None
                C2_lasttime = None
                C2_endpoints = None
                C2_asn = None
                C2_asn_org = None
                C2_country = None

                # Try to affect
                try:
                    C2_ip = one_C2["ip"]
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"No IP field on this target: {str(one_C2)} ({str(inst)})"
                    )
                    continue
                # A quick bypass when none
                if C2_ip is None:
                    self.helper.connector_logger.error(
                        f"Error on this target: {str(one_C2)}"
                    )
                    continue
                if str(C2_ip) == "None":
                    self.helper.connector_logger.error(
                        f"Error on this target: {str(one_C2)}"
                    )
                    continue
                try:
                    C2_key = one_C2["key"]
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'key' error: {str(inst)}"
                    )
                    # Use the ``None`` sentinel (not the literal string
                    # ``"None"``): downstream ``create_stix_object``
                    # creates a ``DomainName`` observable whenever
                    # ``target["key"] != target["ip"]``, which would
                    # otherwise emit a ``DomainName(value="None")``
                    # SCO (invalid + noisy data in the platform).
                    C2_key = None
                if isinstance(C2_key, str) and not C2_key.strip():
                    C2_key = None
                try:
                    # ``datetime`` is imported as the module (``import datetime``),
                    # so ``fromtimestamp`` lives on ``datetime.datetime``, not on
                    # the module itself.
                    #
                    # ``tz=datetime.timezone.utc`` is mandatory: the
                    # BeaconBeagle API exposes ``Firsttime`` / ``lasttime``
                    # as Unix epoch seconds (UTC by definition), and the
                    # downstream ``create_stix_object`` calls
                    # ``.replace(tzinfo=datetime.timezone.utc)`` on the
                    # parsed value. Without ``tz=`` here ``fromtimestamp``
                    # returns a *naive* local-time datetime, the bare
                    # ``replace(tzinfo=...)`` then mis-labels it as UTC,
                    # and every relationship / indicator the connector
                    # emits ends up off by the container's UTC offset.
                    # All sibling ``datetime.now()`` fallbacks are
                    # tz-aware for the same reason.
                    C2_Firsttime = datetime.datetime.fromtimestamp(
                        one_C2["Firsttime"], tz=datetime.timezone.utc
                    )
                except Exception as inst:
                    C2_Firsttime = datetime.datetime.now(datetime.timezone.utc)
                    self.helper.connector_logger.debug(
                        f"Reading 'Firsttime' error: {str(inst)}"
                    )
                try:
                    C2_lasttime = datetime.datetime.fromtimestamp(
                        one_C2["lasttime"], tz=datetime.timezone.utc
                    )
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'lasttime' error: {str(inst)}"
                    )
                    # Honour ``BEACONBEAGLE_LINKS_DURATION`` as the
                    # documented fallback window when the BeaconBeagle
                    # payload omits ``lasttime`` — the indicators
                    # downstream get a bounded ``valid_until = valid_from +
                    # links_duration`` instead of an arbitrary ``now()``
                    # that would silently expand every indicator's
                    # validity window past the operator's configured limit.
                    fallback_start = (
                        C2_Firsttime
                        if C2_Firsttime is not None
                        else datetime.datetime.now(datetime.timezone.utc)
                    )
                    C2_lasttime = fallback_start + datetime.timedelta(
                        hours=int(self.beaconbeagle_links_duration)
                    )
                try:
                    C2_endpoints = one_C2["endpoints"]
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'endpoints' error: {str(inst)}"
                    )
                    C2_endpoints = 0
                # Normalise every "missing or junk" upstream value to the
                # ``None`` sentinel here so the downstream branches in
                # ``create_stix_object`` (BGP whois fallback, country
                # linking, AS linking) have a single condition to test
                # (``is None``) instead of having to special-case ``0``,
                # ``""`` and the literal string ``"None"`` separately.
                # The previous shape mapped missing values to ``0`` /
                # ``""`` then later compared ``str(...) == "None"``, so
                # the BGP / country / AS branches silently never ran on
                # the common "missing key" case and BeaconBeagle payloads
                # without those fields produced ``AutonomousSystem(number=0)``
                # / ``Location(country="")`` SCOs.
                try:
                    C2_asn = one_C2["asn"]
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'asn' error: {str(inst)}"
                    )
                    C2_asn = None
                try:
                    C2_asn_int = int(C2_asn) if C2_asn is not None else None
                except (TypeError, ValueError):
                    C2_asn_int = None
                C2_asn = C2_asn_int if (C2_asn_int and C2_asn_int > 0) else None
                try:
                    C2_asn_org = one_C2["asn_org"]
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'asn_org' error: {str(inst)}"
                    )
                    C2_asn_org = None
                if isinstance(C2_asn_org, str) and not C2_asn_org.strip():
                    C2_asn_org = None
                try:
                    C2_country = one_C2["country"]
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'country' error: {str(inst)}"
                    )
                    C2_country = None
                if isinstance(C2_country, str) and not C2_country.strip():
                    C2_country = None

                One_C2 = {
                    "ip": C2_ip,
                    "key": C2_key,
                    "Firsttime": C2_Firsttime,
                    "lasttime": C2_lasttime,
                    "endpoints": C2_endpoints,
                    "asn": C2_asn,
                    "as_org": C2_asn_org,
                    "Country": C2_country,
                    "FullData": None,
                    "Configs": [],
                    "URLs": [],
                    "UserAgents": [],
                    "SpawnTos": [],
                    "WaterMarks": [],
                }

                if self.beaconbeagle_add_urls:
                    # we have to get more data from BeaconBeagle API for this C2
                    url_more_info = f"https://beaconbeagle.com/api/v1/c2/{C2_ip}"
                    self.helper.connector_logger.debug(
                        f" Add url> Retreiving raw more data at : {url_more_info}."
                    )
                    try:
                        More_Data = requests.get(
                            url_more_info,
                            headers=headers,
                            verify=True,
                            timeout=(10, 60),
                        )
                        self.helper.connector_logger.debug(
                            f"We get a response from BeaconBeagle API c2: {More_Data.status_code}."
                        )
                        if More_Data.status_code != 200:
                            self.helper.connector_logger.error(
                                f"Error while getting data from BeaconBeagle API C2 details: {More_Data.status_code} for {url_more_info}"
                            )
                        else:
                            urls_json = More_Data.json()
                            One_C2["FullData"] = urls_json
                            One_C2["URLs"] = urls_json["URLs"]

                            # Watermark
                            for one_endpoint in urls_json["Endpoints"].keys():
                                for one_seenin in urls_json["Endpoints"][one_endpoint][
                                    "seen_in"
                                ]:
                                    One_C2["WaterMarks"].append(one_seenin["watermark"])

                            if self.beaconbeagle_add_useragent:
                                # We retreive conf hashes
                                for one_endpoint in urls_json["Endpoints"].keys():
                                    for one_seenin in urls_json["Endpoints"][
                                        one_endpoint
                                    ]["seen_in"]:
                                        # Local variable name was ``hash`` which
                                        # shadowed Python's built-in ``hash()`` and
                                        # made debugging / linting noisier. Renamed
                                        # to ``config_hash`` to match the upstream
                                        # field name and avoid the shadow.
                                        config_hash = one_seenin["config_hash"]
                                        try:
                                            url_config = f"https://beaconbeagle.com/api/v1/configs/{config_hash}"
                                            config_ok = False
                                            self.helper.connector_logger.debug(
                                                f" Add useragent 1 > Retreiving raw config at : {url_config}."
                                            )
                                            Config_Data = requests.get(
                                                url_config,
                                                headers=headers,
                                                verify=True,
                                                timeout=(10, 60),
                                            )
                                            self.helper.connector_logger.debug(
                                                f"We get a response from BeaconBeagle API c2: {Config_Data.status_code}."
                                            )
                                            if Config_Data.status_code != 200:
                                                self.helper.connector_logger.error(
                                                    f"Error while getting data from BeaconBeagle API config hash: {Config_Data.status_code}, let's get out of here without data for {url_config}"
                                                )
                                            else:
                                                ua_json = Config_Data.json()
                                                One_C2["Configs"].append(ua_json)
                                                One_C2["UserAgents"].append(
                                                    ua_json["config"]["settings"][
                                                        "SETTING_USERAGENT"
                                                    ]
                                                )

                                                for one_spawn in [
                                                    "SETTING_SPAWNTO",
                                                    "SETTING_SPAWNTO_X86",
                                                    "SETTING_SPAWNTO_X64",
                                                ]:
                                                    if (
                                                        one_spawn
                                                        in ua_json["config"][
                                                            "settings"
                                                        ].keys()
                                                    ):
                                                        process = ua_json["config"][
                                                            "settings"
                                                        ][one_spawn]
                                                        if (
                                                            not process
                                                            in One_C2["SpawnTos"]
                                                            and not process
                                                            == "00000000000000000000000000000000"
                                                        ):
                                                            One_C2["SpawnTos"].append(
                                                                process
                                                            )
                                                config_ok = True

                                            if not config_ok:
                                                # Let's try another way
                                                url_config = f"https://beaconbeagle.com/data/{one_seenin['beacon_ip']}-{one_seenin['beacon_port']}_{one_seenin['arch']}config.json"
                                                self.helper.connector_logger.debug(
                                                    f" Add useragent 2 > Retreiving raw config at : {url_config}."
                                                )
                                                Config_Data = requests.get(
                                                    url_config,
                                                    headers=headers,
                                                    verify=True,
                                                    timeout=(10, 60),
                                                )
                                                self.helper.connector_logger.debug(
                                                    f"We get a response from BeaconBeagle API c2: {Config_Data.status_code}."
                                                )
                                                if Config_Data.status_code != 200:
                                                    self.helper.connector_logger.error(
                                                        f"Error while getting data from BeaconBeagle API config hash type 2: {Config_Data.status_code}, let's get out of here without data for {url_config}"
                                                    )
                                                else:
                                                    ua_json = Config_Data.json()
                                                    One_C2["Configs"].append(ua_json)
                                                    One_C2["UserAgents"].append(
                                                        ua_json["config"]["settings"][
                                                            "SETTING_USERAGENT"
                                                        ]
                                                    )

                                                    for one_spawn in [
                                                        "SETTING_SPAWNTO",
                                                        "SETTING_SPAWNTO_X86",
                                                        "SETTING_SPAWNTO_X64",
                                                    ]:
                                                        if (
                                                            one_spawn
                                                            in ua_json["config"][
                                                                "settings"
                                                            ].keys()
                                                        ):
                                                            process = ua_json["config"][
                                                                "settings"
                                                            ][one_spawn]
                                                            if (
                                                                not process
                                                                in One_C2["SpawnTos"]
                                                                and not process
                                                                == "00000000000000000000000000000000"
                                                            ):
                                                                One_C2[
                                                                    "SpawnTos"
                                                                ].append(process)
                                                    config_ok = True
                                        except Exception as inst:
                                            self.helper.connector_logger.error(
                                                f" No way to retreive config {config_hash}  ({str(inst)})."
                                            )
                    except Exception as inst:
                        self.helper.connector_logger.error(
                            f" No way to retreive C2 info {C2_ip}  ({str(inst)})."
                        )
                # We add it to our list
                beaconbeagle_result.append(One_C2)

            return beaconbeagle_result
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while getting intelligence from BeaconBeagle: {e}"
            )
        return []

    def DictToText(self, DictObj, ret="\r\n"):
        output = ""
        for one_key in DictObj.keys():
            output += " - " + str(one_key) + ":"
            # ``type(x) is []`` is always false: ``type(x)`` returns the
            # ``list`` class, never a fresh empty list literal. Use
            # ``isinstance`` so list / tuple values are actually expanded
            # into the multi-line bullet form they were meant to render in.
            if isinstance(DictObj[one_key], (list, tuple)):
                output += ret
                for one_elemn in DictObj[one_key]:
                    output += "    - " + str(one_elemn) + ret
            else:
                output += str(DictObj[one_key]) + ret
        return output

    def GetCSVersion(self, text_raw):
        # 1. Extraction de la version (votre regex A.B.C.D)
        match = re.search(r"\d+(\.\d+){0,3}", text_raw)
        if not match:
            return "0.0.0.0"
        version_found = match.group(0)
        # 2. Découpage des segments existants
        segments = version_found.split(".")
        # 3. Compléter avec des "0" jusqu'à atteindre 4 segments
        while len(segments) < 4:
            segments.append("0")
        # 4. Re-assemblage
        return ".".join(segments)

    def GetFilename(self, text_raw):
        if "\\" in text_raw:
            return text_raw.split("\\")[-1]
        if "/" in text_raw:
            return text_raw.split("/")[-1]
        return text_raw.split("/")[-1]

    def get_infos_whois(self, ip_to_check):
        """Run ``whois -h bgp.tools -v <ip>`` and parse the data line.

        Returns a dict ``{"asn": int|None, "as_org": str|None,
        "country": str|None}`` on success, or ``None`` on any failure
        (missing ``whois`` binary, timeout, non-zero exit, malformed
        output, unexpected exception). The single ``Dict-or-None``
        contract removes the previous brittle string-sentinel shape
        (``"Process error"`` / ``"Unknown error"``) that forced the
        caller into ``if "Process error" in str(whoisdata)`` checks
        and made it easy to misuse from any new call site.

        ``timeout=30`` matches the HTTP read timeout used by the
        BeaconBeagle ``requests.get`` calls (``(10, 60)``) and
        bounds the per-IP lookup so a hung ``bgp.tools`` or a
        network partition cannot stall the entire run loop
        indefinitely. ``TimeoutExpired`` is funneled into the
        ``None`` return below so the caller's existing
        recoverable-error path (skip the BGP enrichment for this
        target, keep going with the rest of the bundle) handles
        it without further changes.

        ``-v`` and the IP are passed as separate ``subprocess`` argv
        entries — the previous shape concatenated them into a single
        argument with a leading space, which ``whois`` parses as an
        unknown query string and rejects.
        """
        try:
            cmd = ["whois", "-h", "bgp.tools", "-v", str(ip_to_check)]
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True, timeout=30
            )

            lines = result.stdout.strip().splitlines()

            # bgp.tools often emits a warning banner on the first line, so we
            # walk the output to find the header row before slicing columns.
            header_idx = next(
                i for i, line in enumerate(lines) if "AS" in line and "|" in line
            )
            headers = [h.strip() for h in lines[header_idx].split("|")]
            data_line = [v.strip() for v in lines[header_idx + 1].split("|")]

            dataDict = dict(zip(headers, data_line))
            output = {"asn": None, "as_org": None, "country": None}

            if "AS" in dataDict:
                output["asn"] = int(str(dataDict["AS"]))
            if "AS Name" in dataDict:
                output["as_org"] = str(dataDict["AS Name"])
            if "CC" in dataDict:
                output["country"] = str(dataDict["CC"])

            return output

        except FileNotFoundError:
            # ``whois`` binary not in the container — log once at error
            # level so the operator can install it (or disable
            # ``BEACONBEAGLE_SEARCH_BGPAS``); return ``None`` so the
            # caller's recoverable-error path skips BGP for this target.
            self.helper.connector_logger.error(
                "`whois` command not found in PATH — install the `whois` "
                "package in the image or disable BEACONBEAGLE_SEARCH_BGPAS."
            )
            return None
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            StopIteration,
            IndexError,
        ):
            return None
        except Exception as e:
            self.helper.connector_logger.error(
                f"Unexpected error during whois lookup for {ip_to_check}: {e}"
            )
            return None

    def get_type_pure_regex(self, text):
        text = text.strip()

        # IP detection uses the standard-library ``ipaddress`` module rather
        # than hand-written regexes: it exhaustively recognises every valid
        # IPv4 / IPv6 shape (including compressed and IPv4-mapped IPv6) and
        # removes a whole class of false-negative bugs the previous regexes
        # were prone to.
        try:
            return "IPv4" if ipaddress.ip_address(text).version == 4 else "IPv6"
        except ValueError:
            pass

        # Non-IP values keep the regex classifier for hashes / domains.
        patterns = {
            # Hashes (strict hexadecimal)
            "MD5": r"^[a-fA-F0-9]{32}$",
            "SHA256": r"^[a-fA-F0-9]{64}$",
            "SHA512": r"^[a-fA-F0-9]{128}$",
            # Domain: labels of letters/digits/hyphens ending in a 2+ char TLD
            "Domain": r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$",
        }

        for label, pattern in patterns.items():
            if re.fullmatch(pattern, text, re.IGNORECASE if label == "Domain" else 0):
                return label

        return "Unknown"

    def search_id_in_list(self, ObjList, id):
        for elem in ObjList:
            if elem["id"] == id:
                return True
        return False

    def create_stix_object(self, target, identity_id, start_time=None, stop_time=None):
        # identity_id = OCTI Identity ID for BeaconBeagle
        stix_objects = []
        # self.helper.connector_logger.debug(target)
        # We generate STIX objects from each domain entry
        description = (
            "Imported from BeaconBeagle API at "
            + datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
            + ".  \n"
        )
        description += "All informations:  \n"

        description += self.DictToText(target, "  \n")

        # ``target["Firsttime"]`` / ``target["lasttime"]`` are already
        # tz-aware ``datetime`` objects produced by the fetch path
        # (``beaconbeagle_api_get_list`` uses
        # ``datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)``).
        # Use them as-is rather than round-tripping through
        # ``str(...)`` + ``fromisoformat(...)`` + ``replace(tzinfo=...)``,
        # which (a) does extra work for no gain on the happy path and
        # (b) used to silently mis-label naive local-time values as
        # UTC back when the upstream `fromtimestamp` had no `tz=`.
        # Fall back to the `target.get(...)` value only for the
        # exotic case of an upstream caller passing in something
        # unexpected; an `isinstance` guard keeps the contract
        # explicit so non-`datetime` payloads do not slip through
        # to STIX as raw strings.
        if start_time is None:
            value = target.get("Firsttime")
            if isinstance(value, datetime.datetime):
                start_time = value
            else:
                self.helper.connector_logger.error(
                    f"Firsttime is not a datetime ({type(value).__name__}), "
                    "start_time set to None."
                )

        if stop_time is None:
            value = target.get("lasttime")
            if isinstance(value, datetime.datetime):
                stop_time = value
            else:
                self.helper.connector_logger.error(
                    f"lasttime is not a datetime ({type(value).__name__}), "
                    "stop_time set to None."
                )

        # STIX: Create Observables
        self.helper.connector_logger.debug("New target to process")
        try:
            Observables = []
            master_observable_id = None
            ip_add = target["ip"]
            domain = ""
            # We have two case v4 or v6
            IP_Type = self.get_type_pure_regex(ip_add)
            if IP_Type == "IPv4":
                self.helper.connector_logger.debug(f" > Target has an ip: {ip_add}.")
                observable_ip = stix2.IPv4Address(
                    value=ip_add,
                    object_marking_refs=[self.beaconbeagle_marking],
                    custom_properties={
                        "x_opencti_score": 60,
                        "x_opencti_description": description,
                        "x_opencti_created_by_ref": identity_id,
                        "x_opencti_labels": ["CobaltStrike", "BeaconBeagle"],
                    },
                )
            elif IP_Type == "IPv6":
                self.helper.connector_logger.debug(f" > Target has an ip: {ip_add}.")
                observable_ip = stix2.IPv6Address(
                    value=ip_add,
                    object_marking_refs=[self.beaconbeagle_marking],
                    custom_properties={
                        "x_opencti_score": 60,
                        "x_opencti_description": description,
                        "x_opencti_created_by_ref": identity_id,
                        "x_opencti_labels": ["CobaltStrike", "BeaconBeagle"],
                    },
                )
            else:
                self.helper.connector_logger.error(
                    f" > This is not an ip (v4 or v6): {ip_add}."
                )
                return None
            Observables.append(observable_ip)
            stix_objects.append(observable_ip)
            master_observable_id = observable_ip["id"]

            # We have to deal with case key is a domain.
            # Skip when ``key`` is missing (``None`` sentinel from the
            # normalised fetch path) or equals the IP — the previous
            # ``if not target["key"] == target["ip"]`` shape would
            # emit a ``DomainName(value=None)`` SCO on the
            # "missing key" path (which the worker then rejects).
            target_key = target.get("key")
            if (
                target_key
                and isinstance(target_key, str)
                and target_key.strip()
                and target_key != target["ip"]
            ):
                # we have a domain to add
                domain = target_key
                observable_dom = stix2.DomainName(
                    value=domain,
                    object_marking_refs=[self.beaconbeagle_marking],
                    custom_properties={
                        "x_opencti_score": 80,
                        "x_opencti_description": description,
                        "x_opencti_created_by_ref": identity_id,
                        "x_opencti_labels": ["CobaltStrike", "BeaconBeagle"],
                    },
                )
                Observables.append(observable_dom)
                stix_objects.append(observable_dom)
                master_observable_id = observable_dom["id"]
                del observable_dom

            # IF requested, we make a BGP Whois lookup to get more infos for ASN and Country.
            # Use truthy ``None`` / ``0`` / ``""`` checks against the
            # values produced by the normalised fetch path — the previous
            # ``str(...) == "None"`` shape never fired on the common
            # "missing key" case where missing ``asn`` / ``country``
            # were ``0`` / ``""`` (now ``None`` after normalisation).
            if self.beaconbeagle_search_bgpas:
                try:
                    if not target.get("asn") or not target.get("Country"):
                        self.helper.connector_logger.debug(
                            f"     > Infos does not include AS ou Country, Whois bgp tool for {target['ip']}"
                        )
                        # ``get_infos_whois`` returns a dict on success
                        # and ``None`` on any failure (missing binary,
                        # timeout, non-zero exit, malformed output, …)
                        # so the caller has a single contract to test
                        # against instead of brittle ``str(...)`` matching
                        # against ``"Process error"`` / ``"Unknown error"``
                        # sentinels. ``get_infos_whois`` already logged the
                        # failure at error level for the FileNotFoundError /
                        # generic Exception paths; the silent ``CalledProcessError``
                        # / ``TimeoutExpired`` / parsing-failure path gets
                        # a debug log here so an operator chasing missing
                        # BGP enrichment can still see why it was skipped.
                        whoisdata = self.get_infos_whois(target["ip"])
                        if whoisdata is None:
                            self.helper.connector_logger.debug(
                                f"     > Whois bgp tool returned no data for {target['ip']}, "
                                "skipping BGP enrichment for this target."
                            )
                        else:
                            self.helper.connector_logger.debug(
                                f"     > Whois bgp tool said {whoisdata}"
                            )
                            if whoisdata["asn"] is not None:
                                target["asn"] = whoisdata["asn"]
                            if whoisdata["as_org"] is not None:
                                target["as_org"] = whoisdata["as_org"]
                            if whoisdata["country"] is not None:
                                target["Country"] = whoisdata["country"]
                except Exception as inst:
                    self.helper.connector_logger.error(
                        f"Error no way to make whois bgp for {target['ip']} with error {inst}"
                    )

            if self.beaconbeagle_link_country:
                try:
                    # Skip when Country is missing (``None`` sentinel)
                    # or whitespace — the previous ``str(...) == "None"``
                    # shape silently created ``Location(country="")``
                    # SCOs whenever the BeaconBeagle payload had no
                    # country field (now normalised to ``None`` upstream)
                    # *and* the BGP whois fallback also failed.
                    country_val = target.get("Country")
                    if (
                        not country_val
                        or not isinstance(country_val, str)
                        or not country_val.strip()
                    ):
                        self.helper.connector_logger.warning(
                            f"     > Target IP's Country is {country_val}, we skip this one."
                        )
                    else:
                        self.helper.connector_logger.debug(
                            f"     > Target IP is in {target['Country']}, linking country."
                        )
                        # ``pycti.Location.generate_id`` expects
                        # ``(name, location_type)``; passing a STIX
                        # pattern string here would produce unstable IDs
                        # and break Location deduplication across runs.
                        #
                        # ``name`` / ``object_marking_refs`` /
                        # ``created_by_ref`` are added so the SDO carries
                        # the same provenance + marking as every other
                        # object the connector emits: ``stix2.Location``
                        # requires a non-empty ``name`` (the constructor
                        # raises ``MissingPropertiesError`` otherwise),
                        # and unmarked / unattributed location objects
                        # break the platform's TLP-gating + audit trail.
                        country_host = stix2.Location(
                            id=Location.generate_id(target["Country"], "Country"),
                            name=target["Country"],
                            country=target["Country"],
                            created_by_ref=identity_id,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_score": 50,
                            },
                        )
                        self.helper.connector_logger.debug(
                            f"     > Target TLD {target['Country']} is {country_host['country']}."
                        )
                        # STIX: StixCoreRelationship country --> IP
                        self.helper.connector_logger.debug(
                            f"    [+] StixCoreRelationship creation between Country and IP ({country_host['country']} > {observable_ip['value']})."
                        )
                        relation_TC = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                country_host["id"],
                                observable_ip["id"],
                                start_time=start_time,
                            ),
                            source_ref=country_host["id"],
                            target_ref=observable_ip["id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_score": 50,
                                "x_opencti_labels": ["BeaconBeagle"],
                            },
                            description=f"Has hosted a CobaltStrike since {start_time}. (Link IPCountry)",
                        )
                        stix_objects.append(country_host)
                        stix_objects.append(relation_TC)
                        del country_host, relation_TC
                except Exception as inst:
                    self.helper.connector_logger.error(
                        f"Error no way to link country for {target['ip']} with error {inst}"
                    )

            if self.beaconbeagle_link_bgpas:
                # Skip when ASN is missing or non-positive — the previous
                # ``str(...) == "None"`` shape silently created
                # ``AutonomousSystem(number=0)`` (reserved / invalid)
                # whenever the BeaconBeagle payload had no ``asn``
                # field (now normalised to ``None`` upstream) *and* the
                # BGP whois fallback also failed.
                asn_val = target.get("asn")
                try:
                    asn_int = int(asn_val) if asn_val is not None else None
                except (TypeError, ValueError):
                    asn_int = None
                if not asn_int or asn_int <= 0:
                    self.helper.connector_logger.warning(
                        f"     > Target IP's ASN is {asn_val}, we skip this one."
                    )
                else:
                    try:
                        # ``asn_int`` is the validated, positive int from
                        # the guard above; reuse it instead of re-casting
                        # ``target["asn"]`` (the latter could in theory
                        # have been mutated to something non-castable
                        # between the guard and the construction).
                        # ``as_org`` may legitimately be unknown (the
                        # bgp.tools whois call can return only ASN), so
                        # fall back to ``"AS<n>"`` instead of passing
                        # ``None`` / ``""`` as the SCO ``name``.
                        as_org_val = target.get("as_org")
                        if not as_org_val or not str(as_org_val).strip():
                            as_org_val = f"AS{asn_int}"
                        self.helper.connector_logger.debug(
                            f"     > Target IP is in AS {asn_int} {as_org_val}, linking AS BGP."
                        )
                        description_as = f"This AS {asn_int} {as_org_val} was hosting a {self.beaconbeagle_link_tool} Configuration at {ip_add}"
                        as_stix = stix2.AutonomousSystem(
                            number=asn_int,
                            name=as_org_val,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_description": description_as,
                                "x_opencti_score": 60,
                                "x_opencti_labels": [],
                                "x_opencti_created_by_ref": identity_id,
                            },
                        )

                        # STIX: StixCoreRelationship AS BGP --> Targeted Country
                        self.helper.connector_logger.debug(
                            f"    [+] StixCoreRelationship creation between AS BGP and IP ({as_stix['number']} > {observable_ip['value']})."
                        )
                        relation_TAS = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                as_stix["id"],
                                observable_ip["id"],
                                start_time=start_time,
                            ),
                            source_ref=as_stix["id"],
                            target_ref=observable_ip["id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_score": 50,
                                "x_opencti_labels": ["BeaconBeagle"],
                            },
                            description=f"Has hosted a CobaltStrike since {start_time}. (Link IP AS)",
                        )
                        stix_objects.append(as_stix)
                        stix_objects.append(relation_TAS)
                        del as_stix, relation_TAS
                    except Exception as inst:
                        self.helper.connector_logger.error(
                            f"Error no way to link AS with {target['ip']} with error {inst}"
                        )

            # Indicator Creation
            try:
                if IP_Type == "IPv4":
                    ip_pattern = f"[ipv4-addr:value = '{ip_add}']"
                elif IP_Type == "IPv6":
                    ip_pattern = f"[ipv6-addr:value = '{ip_add}']"
                else:
                    self.helper.connector_logger.debug(
                        f" Indicator Creation > This is not an ip (v4 or v6): {ip_add}, we can't create an indicator for this one."
                    )
                    # ``raise (str, str)`` raises a tuple, which Python
                    # immediately rejects with ``TypeError`` because only
                    # ``BaseException`` instances/classes are raisable.
                    # Raise a concrete exception type instead.
                    raise ValueError(
                        f"Cannot create an indicator for {ip_add!r}: "
                        "value is not a valid IPv4 or IPv6 address."
                    )
                # ``valid_from`` / ``valid_until`` are the STIX 2.1
                # fields that describe the *observation window* of an
                # Indicator (when its pattern is expected to match
                # malicious activity). ``created`` / ``modified`` are
                # SDO-lifecycle timestamps and are set by the
                # ``stix2`` library / OpenCTI automatically. Using
                # ``modified=stop_time`` was forcing a new SDO version
                # on every run whose ``stop_time`` shifted (which is
                # every run for a still-active C2), causing needless
                # indicator churn in OpenCTI's history.
                indicator_ip = stix2.Indicator(
                    id=Indicator.generate_id(ip_pattern),
                    name=ip_add,
                    pattern=ip_pattern,
                    pattern_type="stix",
                    description=description,
                    created_by_ref=identity_id,
                    valid_from=start_time,
                    valid_until=stop_time,
                    # confidence=60,
                    object_marking_refs=[self.beaconbeagle_marking],
                    custom_properties={
                        "x_opencti_score": 60,
                        "x_opencti_main_observable_type": f"{IP_Type}-Addr",
                    },
                )
                # ``Indicator based-on Observable`` is the STIX 2.1
                # idiomatic shape (the indicator's pattern is *based on*
                # the observable's concrete value) and what OpenCTI's
                # UI / dedup logic expects under the "Based on" tab. The
                # previous ``related-to`` shape worked but broke that
                # navigation and the platform's deterministic-id
                # deduplication for indicator/observable pairs.
                relationship_indobsip = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "based-on", indicator_ip["id"], observable_ip["id"]
                    ),
                    relationship_type="based-on",
                    source_ref=indicator_ip["id"],
                    target_ref=observable_ip["id"],
                    created_by_ref=identity_id,
                    object_marking_refs=[self.beaconbeagle_marking],
                )
                stix_objects.append(indicator_ip)
                stix_objects.append(relationship_indobsip)
            except Exception as inst:
                # Surface the failure but make sure ``indicator_ip`` /
                # ``relationship_indobsip`` are at least bound so the
                # downstream ``del`` block (left from the original
                # tight-memory shape) cannot ``UnboundLocalError``.
                # The ``stix_objects`` list is the single source of
                # truth for what ends up in the bundle, so this only
                # affects the local lifetime; we already failed to
                # append both objects above.
                self.helper.connector_logger.error(
                    f"Error no way create Indicator for {target['ip']} with error {inst}"
                )
                indicator_ip = None
                relationship_indobsip = None

            if len(self.beaconbeagle_link_watermark) > 1:
                try:
                    self.helper.connector_logger.debug(
                        f"    [+] We save {self.beaconbeagle_link_tool} Licences watermarks"
                    )
                    for one_licence in target["WaterMarks"]:
                        self.helper.connector_logger.debug(
                            f"      Adding {self.beaconbeagle_link_tool} Licence {one_licence}"
                        )
                        description_licence = f"This {self.beaconbeagle_link_tool} licence {one_licence} was seen used on {ip_add} {domain}"
                        # ``pycti.CustomObservableText`` is the
                        # deterministic-id STIX SCO equivalent for the
                        # OpenCTI ``Text`` observable type. The previous
                        # ``self.helper.api.stix_cyber_observable.create``
                        # shape (a) made a live GraphQL write
                        # mid-bundle-build (so an error on the next line
                        # would leave a half-written platform state with
                        # no bundle to retry against), (b) bypassed
                        # deterministic id generation so re-runs created
                        # duplicates rather than deduplicating, and
                        # (c) mutated the GraphQL response dict to
                        # impersonate a STIX object which is fragile
                        # against any pycti schema change. The
                        # ``CustomObservableText`` form is the
                        # canonical pattern every other connector in
                        # the repo uses (see ``onyphe`` /
                        # ``recorded-future`` / ``misp``).
                        observable_txt = CustomObservableText(
                            value=str(one_licence)
                            + str(self.beaconbeagle_link_watermark),
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_created_by_ref": identity_id,
                                "x_opencti_score": 60,
                                "x_opencti_description": description_licence,
                                "x_opencti_labels": ["CobaltStrike"],
                            },
                        )
                        Observables.append(observable_txt)
                        stix_objects.append(observable_txt)
                except Exception as inst:
                    self.helper.connector_logger.error(
                        f"Error no way create watermak(licence) for {target['ip']} with error {inst}"
                    )

            del observable_ip, indicator_ip, relationship_indobsip
            # We create URLs Observables if any.
            # The previous shape was a four-level
            # ``if not None is target: if target.get("FullData"): if not
            # None is target.get("FullData"): if target.get("FullData").get(
            # "URLs"):`` guard chain — confusing, partially redundant
            # (``target.get("FullData")`` truthy already implies it is
            # not ``None``) and noisy in tracebacks. Collapse to two
            # explicit ``or`` defaults so the intent is obvious:
            # "iterate over ``target["FullData"]["URLs"]`` if present,
            # otherwise skip the block".
            try:
                full_data = target.get("FullData") or {}
                for one_url in full_data.get("URLs") or []:
                    description_url = (
                        f"This URL was used by {self.beaconbeagle_link_tool} "
                        f"on {ip_add}"
                    )
                    self.helper.connector_logger.debug(
                        f" > Target has a url: {one_url}."
                    )
                    observable_url = stix2.URL(
                        value=one_url,
                        object_marking_refs=[self.beaconbeagle_marking],
                        custom_properties={
                            "x_opencti_score": 60,
                            "x_opencti_description": description_url,
                            "x_opencti_created_by_ref": identity_id,
                            "x_opencti_labels": ["CobaltStrike", "C2"],
                        },
                    )
                    Observables.append(observable_url)
                    # Indicator Creation — URLs frequently
                    # carry single quotes or backslashes
                    # (e.g. encoded query strings); escape
                    # them so the resulting STIX pattern
                    # stays valid and ``Indicator.generate_id``
                    # produces a stable, deduplicating id.
                    _url_pattern = f"[url:value = '{_stix_pattern_escape(one_url)}']"
                    # See the IP Indicator block above
                    # for the ``valid_from`` /
                    # ``valid_until`` rationale (STIX
                    # 2.1 observation window, not SDO
                    # lifecycle).
                    indicator_url = stix2.Indicator(
                        id=Indicator.generate_id(_url_pattern),
                        name=one_url,
                        pattern=_url_pattern,
                        pattern_type="stix",
                        description=description,
                        created_by_ref=identity_id,
                        valid_from=start_time,
                        valid_until=stop_time,
                        # confidence=60,
                        object_marking_refs=[self.beaconbeagle_marking],
                        custom_properties={
                            "x_opencti_score": 60,
                            "x_opencti_description": description_url,
                            "x_opencti_main_observable_type": "Url",
                        },
                    )
                    # ``Indicator based-on Observable``
                    # — see the IP indicator-relationship
                    # block above for rationale.
                    relationship_indobsurl = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "based-on",
                            indicator_url["id"],
                            observable_url["id"],
                        ),
                        relationship_type="based-on",
                        source_ref=indicator_url["id"],
                        target_ref=observable_url["id"],
                        created_by_ref=identity_id,
                        object_marking_refs=[self.beaconbeagle_marking],
                    )
                    stix_objects.append(observable_url)
                    stix_objects.append(indicator_url)
                    stix_objects.append(relationship_indobsurl)
                    del (
                        observable_url,
                        indicator_url,
                        relationship_indobsurl,
                    )

            except Exception as inst:
                self.helper.connector_logger.error(
                    f"Error no way create URLs for {target['ip']} with error {inst}"
                )

            # We create User Agent / Software / Process Observables  if any
            try:
                if target.get("Configs"):
                    for one_config in target["Configs"]:
                        self.helper.connector_logger.debug(" > Target Config ")
                        # Software Creation
                        self.helper.connector_logger.debug("     > User Agent ")
                        Full_Version = one_config["config"][
                            "version"
                        ]  # "Cobalt Strike 4.8 (Feb 28, 2023)"
                        Version = self.GetCSVersion(
                            one_config["config"]["version"]
                        )  # "4.8"
                        description_software = f"This {Full_Version}  "
                        software_stix = stix2.Software(
                            name=Full_Version,
                            vendor="CobaltStrike",
                            version=Version,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_created_by_ref": identity_id,
                                "x_opencti_score": 60,
                                "x_opencti_description": description_software,
                                "x_opencti_labels": ["CobaltStrike"],
                            },
                        )
                        # User Agent Creation
                        description_ua = f"This user Agent is used in a {Full_Version} Configuration at {ip_add}"
                        UserAgent = one_config["config"]["settings"][
                            "SETTING_USERAGENT"
                        ]  # "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
                        # ``pycti.CustomObservableUserAgent`` produces a
                        # deterministic-id STIX SCO for the OpenCTI
                        # ``User-Agent`` observable type. Replaces the
                        # previous ``self.helper.api.stix_cyber_observable.create``
                        # call (see the watermark-Text block above for
                        # the same rationale: avoid mid-bundle GraphQL
                        # writes, restore deterministic dedup, stop
                        # impersonating a STIX dict by mutating the
                        # GraphQL response shape).
                        user_agent_stix = CustomObservableUserAgent(
                            value=UserAgent,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_created_by_ref": identity_id,
                                "x_opencti_score": 60,
                                "x_opencti_description": description_ua,
                                "x_opencti_labels": ["CobaltStrike"],
                            },
                        )
                        # Indicator Creation for User Agent — UA strings
                        # frequently contain quotes / backslashes that
                        # would otherwise break the STIX pattern and
                        # produce non-deterministic indicator IDs.
                        _ua_pattern = (
                            f"[user-agent:value = '{_stix_pattern_escape(UserAgent)}']"
                        )
                        # See the IP Indicator block above for the
                        # ``valid_from`` / ``valid_until`` rationale
                        # (STIX 2.1 observation window, not SDO
                        # lifecycle).
                        indicator_ua = stix2.Indicator(
                            id=Indicator.generate_id(_ua_pattern),
                            name=UserAgent,
                            pattern=_ua_pattern,
                            pattern_type="stix",
                            description=description_ua,
                            created_by_ref=identity_id,
                            valid_from=start_time,
                            valid_until=stop_time,
                            # confidence=60,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_score": 60,
                                "x_opencti_description": description_ua,
                                # The indicator pattern is
                                # ``[user-agent:value = ...]`` and the
                                # SCO is a ``CustomObservableUserAgent``;
                                # the canonical OpenCTI observable-type
                                # label is ``"User-Agent"`` (see
                                # ``pycti/utils/constants.py``
                                # ``StixCyberObservableTypes.USER_AGENT``).
                                # The previous ``"Software"`` value
                                # broke any UI filter / playbook step
                                # that keys off ``x_opencti_main_observable_type``.
                                "x_opencti_main_observable_type": "User-Agent",
                            },
                        )
                        # ``Indicator based-on Observable`` for the UA
                        # SCO — the indicator pattern is
                        # ``[user-agent:value = ...]``, so the
                        # user-agent observable is what the indicator is
                        # based on (same rationale as the IP / URL
                        # blocks above).
                        relationship_indobsua = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator_ua["id"], user_agent_stix["id"]
                            ),
                            relationship_type="based-on",
                            source_ref=indicator_ua["id"],
                            target_ref=str(user_agent_stix["id"]),
                            created_by_ref=identity_id,
                            object_marking_refs=[self.beaconbeagle_marking],
                        )
                        # Indicator <-> Software stays ``related-to``:
                        # the indicator's pattern is on
                        # ``user-agent:value``, not on a Software
                        # property, so ``based-on`` would be incorrect
                        # here. ``related-to`` captures the looser
                        # "this UA string is associated with this
                        # CobaltStrike software node" semantic.
                        relationship_indobssoft = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", indicator_ua["id"], software_stix["id"]
                            ),
                            relationship_type="related-to",
                            source_ref=indicator_ua["id"],
                            target_ref=str(software_stix["id"]),
                            created_by_ref=identity_id,
                            object_marking_refs=[self.beaconbeagle_marking],
                        )

                        # Add Software if not existing in Observables (can be linked to multiple indicators)
                        if self.search_id_in_list(Observables, software_stix["id"]):
                            self.helper.connector_logger.debug(
                                f"     > Software {software_stix['name']} already in Observables"
                            )
                        else:
                            Observables.append(software_stix)

                        # Add User Agent if not existing in Observables (can be linked to multiple indicators).
                        # ``CustomObservableUserAgent`` carries the UA
                        # string under ``value``, not ``name`` — the
                        # previous ``user_agent_stix['name']`` would
                        # ``KeyError`` on the new SCO shape.
                        if self.search_id_in_list(Observables, user_agent_stix["id"]):
                            self.helper.connector_logger.debug(
                                f"     > User Agent {user_agent_stix['value']} already in Observables"
                            )
                        else:
                            Observables.append(user_agent_stix)

                        # Add Software if not existing in bundles (can be linked to multiple indicators)
                        if self.search_id_in_list(stix_objects, software_stix["id"]):
                            self.helper.connector_logger.debug(
                                f"     > Software {software_stix['name']} already in Stix bundle"
                            )
                        else:
                            stix_objects.append(software_stix)
                        # Add User Agent if not existing in bundles (can be linked to multiple indicators).
                        if self.search_id_in_list(stix_objects, user_agent_stix["id"]):
                            self.helper.connector_logger.debug(
                                f"     > User Agent {user_agent_stix['value']} already in Stix bundle"
                            )
                        else:
                            stix_objects.append(user_agent_stix)

                        stix_objects.append(indicator_ua)
                        stix_objects.append(relationship_indobsua)
                        stix_objects.append(relationship_indobssoft)

                        del (
                            user_agent_stix,
                            indicator_ua,
                            relationship_indobsua,
                            relationship_indobssoft,
                        )

                        # Spawned Process
                        self.helper.connector_logger.debug("     > Spawned Process ")
                        for one_spawn in [
                            "SETTING_SPAWNTO",
                            "SETTING_SPAWNTO_X86",
                            "SETTING_SPAWNTO_X64",
                        ]:
                            if one_spawn in one_config["config"]["settings"].keys():
                                process = one_config["config"]["settings"][one_spawn]

                                if process == "00000000000000000000000000000000":
                                    self.helper.connector_logger.debug(
                                        f"         > Process Skip {process}"
                                    )
                                else:
                                    self.helper.connector_logger.debug(
                                        f"         > Process {process}"
                                    )
                                    # We create Object
                                    description_process = (
                                        f"This process is used in {Full_Version}"
                                    )
                                    # ``stix2.Process`` SCO: only ``command_line``
                                    # is known from the BeaconBeagle config (the
                                    # ``SETTING_SPAWNTO`` value is the spawned
                                    # process's command line). Previously this
                                    # also set ``cwd=process`` (semantically
                                    # wrong — ``cwd`` is the working directory,
                                    # not the command line) and ``pid=0`` (a
                                    # reserved / invalid PID value). Both are
                                    # omitted now so the SCO carries only
                                    # information that is actually known and
                                    # accurate; STIX 2.1 makes every
                                    # ``process`` field optional individually.
                                    #
                                    # ``id=`` is set explicitly via
                                    # ``_generate_process_id`` so re-runs
                                    # against the same ``command_line``
                                    # produce the same ``process--<uuid>``
                                    # id (UUIDv5 of the canonicalised
                                    # ``{"command_line": ...}`` against the
                                    # OpenCTI namespace UUID, matching the
                                    # pycti ``generate_id`` convention).
                                    # ``stix2.Process`` otherwise emits a
                                    # fresh random UUIDv4 every call,
                                    # which (a) defeated OpenCTI dedup,
                                    # (b) broke the
                                    # ``search_id_in_list(stix_objects, …)``
                                    # checks immediately below, and
                                    # (c) leaked Process churn into
                                    # OpenCTI's history on every run.
                                    process_stix = stix2.Process(
                                        id=_generate_process_id(process),
                                        object_marking_refs=[self.beaconbeagle_marking],
                                        command_line=process,
                                        custom_properties={
                                            "x_opencti_created_by_ref": identity_id,
                                            "x_opencti_score": 60,
                                            "x_opencti_description": description_process,
                                            "x_opencti_labels": [
                                                "CobaltStrike",
                                                "BeaconBeagle",
                                            ],
                                        },
                                    )
                                    process_stix_id = process_stix["id"]
                                    # We test if this one is already in bundle list (can be linked to multiple indicators)
                                    if self.search_id_in_list(
                                        stix_objects, process_stix["id"]
                                    ):
                                        self.helper.connector_logger.debug(
                                            f"       [ ] Process {process} already in Stix bundle"
                                        )
                                    else:
                                        # IT's a new one
                                        self.helper.connector_logger.debug(
                                            f"       [+] Not in Stix bundle : {process_stix_id}"
                                        )
                                        stix_objects.append(process_stix)
                                        # We test if this one is already in Observables list (can be linked to multiple indicators)
                                        if self.search_id_in_list(
                                            Observables, process_stix["id"]
                                        ):
                                            self.helper.connector_logger.debug(
                                                f"       [ ] Process {process} already in Observables"
                                            )
                                        else:
                                            # IT's a new one
                                            self.helper.connector_logger.debug(
                                                f"       [+] Not in Observables : {process_stix_id}"
                                            )
                                            Observables.append(process_stix)
                                    del process_stix

                                    # Indicator Creation — escape both
                                    # backslashes AND single quotes so the
                                    # STIX pattern stays valid for any
                                    # ``command_line`` value (the previous
                                    # ``replace("\\", "\\\\")`` shape
                                    # missed embedded single quotes).
                                    _proc_pattern = (
                                        f"[process:command_line = "
                                        f"'{_stix_pattern_escape(process)}']"
                                    )
                                    # Same ``valid_from`` /
                                    # ``valid_until`` convention as the
                                    # IP / URL / UA indicators above
                                    # so every Indicator this connector
                                    # emits carries the same STIX 2.1
                                    # observation-window shape and
                                    # produces stable SDO history in
                                    # OpenCTI across runs.
                                    indicator_proc = stix2.Indicator(
                                        id=Indicator.generate_id(_proc_pattern),
                                        name=f"Spawned process by {self.beaconbeagle_link_tool}",
                                        description=description_process,
                                        pattern_type="stix",
                                        pattern=_proc_pattern,
                                        indicator_types=["malicious-activity"],
                                        created_by_ref=identity_id,
                                        valid_from=start_time,
                                        valid_until=stop_time,
                                        # confidence=60,
                                        object_marking_refs=[self.beaconbeagle_marking],
                                        custom_properties={
                                            "x_opencti_score": 60,
                                            "x_opencti_description": description_process,
                                            "x_opencti_main_observable_type": "Process",
                                            "x_opencti_labels": [
                                                "CobaltStrike",
                                                "BeaconBeagle",
                                            ],
                                        },
                                    )
                                    relationship_indobsproc = stix2.Relationship(
                                        id=StixCoreRelationship.generate_id(
                                            "based-on",
                                            indicator_proc["id"],
                                            process_stix_id,
                                        ),
                                        relationship_type="based-on",
                                        source_ref=indicator_proc["id"],
                                        target_ref=process_stix_id,
                                        created_by_ref=identity_id,
                                        object_marking_refs=[self.beaconbeagle_marking],
                                    )
                                    stix_objects.append(indicator_proc)
                                    stix_objects.append(relationship_indobsproc)
                                    del indicator_proc, relationship_indobsproc
            except Exception as inst:
                self.helper.connector_logger.error(
                    f"Error no way create config elements for {target['ip']} with error {inst}"
                )

            # Linking all to master id (IP adress)
            if not master_observable_id is None:
                for observable_l in Observables:
                    try:
                        if observable_l["id"] == master_observable_id:
                            continue
                        # We have two kind of observable in that list
                        if "standard_id" in observable_l.keys():
                            self.helper.connector_logger.debug(
                                f" [+] StixCoreRelationship creation between MasterObservable and Observable ({master_observable_id} > {observable_l['standard_id']})."
                            )
                            relation_OO = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to",
                                    master_observable_id,
                                    observable_l["standard_id"],
                                    start_time=start_time,
                                ),
                                source_ref=master_observable_id,
                                target_ref=observable_l["standard_id"],
                                relationship_type="related-to",
                                created_by_ref=identity_id,
                                start_time=start_time,
                                object_marking_refs=[self.beaconbeagle_marking],
                                description=f"Link between IP and {observable_l['entity_type']} at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')}. (Link )",
                            )
                            stix_objects.append(relation_OO)
                            del relation_OO
                        else:
                            self.helper.connector_logger.debug(
                                f" [+] StixCoreRelationship creation between MasterObservable and Observable ({master_observable_id} > {observable_l['id']})."
                            )
                            relation_OO = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to",
                                    master_observable_id,
                                    observable_l["id"],
                                    start_time=start_time,
                                ),
                                source_ref=master_observable_id,
                                target_ref=observable_l["id"],
                                relationship_type="related-to",
                                created_by_ref=identity_id,
                                start_time=start_time,
                                object_marking_refs=[self.beaconbeagle_marking],
                                description=f"Link between IP and {observable_l['type']} at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')}. (Link )",
                            )
                            stix_objects.append(relation_OO)
                            del relation_OO
                    except Exception as inst:
                        self.helper.connector_logger.error(
                            f"Error no way create Observable relationship elements for {observable_l['id']} with error {inst}"
                        )

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from target: {str(target)}, error: {e}"
            )
            return None

        # STIX: Linking Tool (StixCoreRelationship)
        # Linking Elements with Tool/Threat-Actor/Attack-Pattern/Country/Campaign if requested
        for observable in Observables:
            if "value" in observable.keys():
                self.helper.connector_logger.debug(
                    f"  -  Working on observable created: {observable['value']}."
                )
            elif "name" in observable.keys():
                self.helper.connector_logger.debug(
                    f"  -  Working on observable created: {observable['name']}."
                )
            else:
                self.helper.connector_logger.debug(
                    f"  -  Working on observable created: {observable['id']}."
                )
            try:
                if self.beaconbeagle_link_tool_id is None:
                    self.helper.connector_logger.debug(
                        "    [-] No Link with Tool requested."
                    )
                else:
                    # STIX: StixCoreRelationship Observable --> Tool
                    # We have two kind of observable in that list
                    if "standard_id" in observable.keys():
                        self.helper.connector_logger.debug(
                            f"    [+] StixCoreRelationship creation between Tool and Observable ({self.beaconbeagle_link_tool} > {observable['standard_id']})."
                        )
                        relation_OT = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                self.beaconbeagle_link_tool_id,
                                observable["standard_id"],
                                start_time=start_time,
                            ),
                            source_ref=self.beaconbeagle_link_tool_id,
                            target_ref=observable["standard_id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            description=f"Was used by {self.beaconbeagle_link_tool} since {start_time}. (Link ObsTool)",
                        )
                        stix_objects.append(relation_OT)
                        del relation_OT
                    else:
                        self.helper.connector_logger.debug(
                            f"    [+] StixCoreRelationship creation between Tool and Observable ({self.beaconbeagle_link_tool} > {observable['id']})."
                        )
                        relation_OT = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                self.beaconbeagle_link_tool_id,
                                observable["id"],
                                start_time=start_time,
                            ),
                            source_ref=self.beaconbeagle_link_tool_id,
                            target_ref=observable["id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            description=f"Was used by {self.beaconbeagle_link_tool} since {start_time}. (Link ObsTool)",
                        )
                        stix_objects.append(relation_OT)
                        del relation_OT
            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error while creating STIX object from Tool: {self.beaconbeagle_link_tool}, error: {e}"
                )
            # STIX: Linking Attack-Pattern (StixCoreRelationship)
            try:
                if self.beaconbeagle_link_ap_id is None:
                    self.helper.connector_logger.debug(
                        "    [-] No Link with Tool requested."
                    )
                else:
                    # STIX: StixCoreRelationship Observable --> Attack-Pattern
                    # We have two kind of observable in that list
                    if "standard_id" in observable.keys():
                        self.helper.connector_logger.debug(
                            f"    [+] StixCoreRelationship creation between Attack-Pattern and Observable ({self.beaconbeagle_link_ap} > {observable['standard_id']})."
                        )
                        relation_OAP = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                self.beaconbeagle_link_ap_id,
                                observable["standard_id"],
                                start_time=start_time,
                            ),
                            source_ref=self.beaconbeagle_link_ap_id,
                            target_ref=observable["standard_id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            description=f"Was used by {self.beaconbeagle_link_ap} since {start_time}. (Link ObsAttackPattern)",
                        )
                        stix_objects.append(relation_OAP)
                        del relation_OAP
                    else:
                        self.helper.connector_logger.debug(
                            f"    [+] StixCoreRelationship creation between Attack-Pattern and Observable ({self.beaconbeagle_link_ap} > {observable['id']})."
                        )
                        relation_OAP = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                self.beaconbeagle_link_ap_id,
                                observable["id"],
                                start_time=start_time,
                            ),
                            source_ref=self.beaconbeagle_link_ap_id,
                            target_ref=observable["id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            description=f"Was used by {self.beaconbeagle_link_ap} since {start_time}. (Link ObsAttackPattern)",
                        )
                        stix_objects.append(relation_OAP)
                        del relation_OAP
            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error while creating STIX object from Attack-Pattern: {self.beaconbeagle_link_ap}, error: {e}"
                )
        # ---------------------------------------------------------------
        return stix_objects

    def create_stix_bundle(self, targeted):
        # create start_date: Now
        # start_date = datetime.datetime.now()
        # create end_date tomoraw 06:00 (usual duration is 24h)
        # end_date = start_date + datetime.timedelta(
        #     hours=self.beaconbeagle_links_duration
        # )

        # Create the Identity for BeaconBeagle Import.
        # - ``id`` is the deterministic pycti id so every connector run
        #   resolves to the same Identity in OpenCTI.
        # - ``created`` / ``modified`` are *not* hardcoded any more:
        #   ``stix2.Identity`` sets sensible defaults (the SDO's
        #   construction timestamp) and OpenCTI deduplicates on ``id``
        #   regardless, so the previous frozen ``"2026-01-01T00:00:00.000Z"``
        #   literals are unnecessary and confusing in audit history.
        # - ``object_marking_refs`` reuses ``self.beaconbeagle_marking``
        #   to stay consistent with every other SDO this connector
        #   emits (Indicator, Tool, AttackPattern, …). Previously this
        #   was hardcoded to ``stix2.TLP_WHITE`` even when the operator
        #   configured a different marking, which silently leaked the
        #   author Identity to ``TLP:WHITE``.
        # - Redundant ``spec_version="2.1"`` / ``type="identity"`` are
        #   dropped: ``stix2`` sets both automatically for ``Identity``
        #   so passing them explicitly is dead noise.
        identity_id = Identity.generate_id(
            name="BeaconBeagle", identity_class="organization"
        )
        identity = stix2.Identity(
            id=identity_id,
            name="BeaconBeagle",
            identity_class="organization",
            object_marking_refs=[self.beaconbeagle_marking],
        )
        stix_objects = [identity, self.beaconbeagle_marking]
        # Creating the tool (CobaltStrike) if needed
        self.beaconbeagle_link_tool_id = None
        try:
            if len(self.beaconbeagle_link_tool) > 0:
                self.helper.connector_logger.debug(
                    f"Tool creation: {self.beaconbeagle_link_tool}."
                )
                # ``pycti.Tool.generate_id`` is name-keyed elsewhere in
                # the repo; passing a STIX pattern string here would
                # produce inconsistent IDs and prevent deduplication on
                # subsequent runs.
                tool = stix2.Tool(
                    id=Tool.generate_id(self.beaconbeagle_link_tool),
                    name=self.beaconbeagle_link_tool,
                    created_by_ref=identity_id,
                    object_marking_refs=[self.beaconbeagle_marking],
                )
                stix_objects.append(tool)
                self.beaconbeagle_link_tool_id = tool["id"]
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from Tool: {self.beaconbeagle_link_tool}, error: {e}"
            )

        # Creating the Attack Patter (T1071 Standard Application Layer Protocol) if needed
        self.beaconbeagle_link_ap_id = None
        try:
            if len(self.beaconbeagle_link_ap) > 0:
                self.helper.connector_logger.debug(
                    f"Attack-Patter Creation: {self.beaconbeagle_link_ap}."
                )
                # ``pycti.AttackPattern.generate_id`` accepts ``(name,
                # mitre_id)``. Many MITRE references are passed as
                # ``"T1071 Standard Application Layer Protocol"``; split the
                # MITRE technique id from the descriptive name when present
                # so generated IDs are deterministic and consistent with
                # other connectors.
                _ap_raw = self.beaconbeagle_link_ap.strip()
                _ap_parts = _ap_raw.split(" ", 1)
                if _ap_parts[0] and re.fullmatch(r"T\d{4}(?:\.\d{3})?", _ap_parts[0]):
                    _ap_mitre_id = _ap_parts[0]
                    _ap_name = _ap_parts[1] if len(_ap_parts) > 1 else _ap_parts[0]
                else:
                    _ap_mitre_id = None
                    _ap_name = _ap_raw
                # ``created_by_ref`` + ``object_marking_refs`` mirror
                # the convention every other SDO this connector emits
                # follows (`Identity`, `Tool`, `Indicator`, …). Without
                # them the AttackPattern lands in the bundle as a
                # marker-free / author-less object, which breaks TLP
                # gating on the platform side and loses the
                # connector-provenance audit trail.
                ddos_attack = stix2.AttackPattern(
                    id=AttackPattern.generate_id(_ap_name, _ap_mitre_id),
                    name=_ap_name,
                    description=(
                        f"Attack pattern linked to {self.beaconbeagle_link_tool} "
                        "traffic seen by BeaconBeagle."
                    ),
                    created_by_ref=identity_id,
                    object_marking_refs=[self.beaconbeagle_marking],
                )
                stix_objects.append(ddos_attack)
                self.beaconbeagle_link_ap_id = ddos_attack["id"]
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from Attack-Patter: {self.beaconbeagle_link_ap}, error: {e}"
            )

        # Finally Creating the Observables from targeted list
        for one_target in targeted:
            stix_object = self.create_stix_object(one_target, identity_id)
            if stix_object:
                stix_objects.extend(stix_object)

        # ----------------------------------------------------

        bundle = stix2.Bundle(
            objects=stix_objects,
            allow_custom=True,
        )
        return bundle

    def opencti_bundle(self, work_id):
        """Build + send the BeaconBeagle bundle for the current run.

        Raises on bundle-build / send failure so the caller
        (``process_data``) can mark the work as in-error AND
        avoid advancing ``last_run`` — the previous shape
        swallowed exceptions here and the caller then reported
        success + advanced state regardless, hiding failed runs
        from operators and from the platform's connector-health
        monitor.
        """
        # Reset the pending dedup hash so a previous run's value can
        # never accidentally be committed against a payload it did not
        # describe (e.g. if the next ``beaconbeagle_api_get_list`` call
        # short-circuits on an empty payload).
        self._pending_payload_hash = None
        # ``beaconbeagle_api_get_list`` now always returns a ``list``
        # (empty list on any "no targets" / error / unchanged-payload
        # path), so a single truthy check covers every short-circuit
        # branch. The previous ``is None`` / ``len(...) == 0`` split
        # only existed because the function used to mix ``return {}``
        # and ``return [...]``.
        targeted = self.beaconbeagle_api_get_list()
        if not targeted:
            self.helper.connector_logger.info(
                "No data retrieved from BeaconBeagle API, skipping bundle creation."
            )
            return
        stix_bundle = self.create_stix_bundle(targeted)
        # ``Bundle.serialize()`` already returns a valid STIX 2.1
        # JSON string. The previous ``json.loads`` /
        # ``json.dumps(..., indent=4)`` round-trip multiplied the
        # CPU + memory cost on every send (potentially hundreds of
        # MB for a busy BeaconBeagle payload) without changing
        # what the worker actually ingests.
        serialized_bundle = stix_bundle.serialize()
        # ``cleanup_inconsistent_bundle=True`` lets the worker drop dangling
        # relationships whose target is absent from the bundle instead of
        # rejecting the whole bundle on MISSING_REFERENCE_ERROR — the
        # repo-wide convention for external-import connectors.
        self.helper.send_stix2_bundle(
            serialized_bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )
        # Only commit the dedup cursor *after* a successful send;
        # a bundle-build / send failure must leave the previous
        # cursor intact so the next run retries the same payload
        # instead of skipping it as "already seen".
        if self._pending_payload_hash is not None:
            current_state = self.helper.get_state() or {}
            self.helper.set_state(
                {
                    **current_state,
                    "last_payload_hash": self._pending_payload_hash,
                }
            )
            self._pending_payload_hash = None

    def process_data(self):
        work_id = None
        try:
            self.helper.connector_logger.info("Synchronizing with BeaconBeagle APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            # ``now`` is tz-aware UTC, so ``isoformat()`` yields
            # ``"2026-05-27T18:00:00+00:00"`` directly. Use this same
            # canonical form for ``friendly_name``, the bootstrap
            # ``last_run`` write, and the post-run ``last_run`` write
            # so the state file and the work-list display agree on a
            # single UTC ISO-8601 representation. The previous shape
            # mixed three formats: ``strftime("%Y-%m-%d %H:%M:%S")``
            # (no tz) for the friendly name + bootstrap state, and
            # ``now.astimezone().isoformat()`` (converted to *local*
            # tz despite ``now`` already being UTC) on subsequent
            # runs — a confusing audit trail and a real footgun for
            # any future filter that parses ``last_run``.
            now_iso = now.isoformat()
            friendly_name = "BeaconBeagle run @ " + now_iso
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            # Read-modify-write the state dict so we never clobber
            # ``last_payload_hash`` (set inside ``opencti_bundle``).
            # The previous ``self.helper.set_state({"last_run": ...})``
            # shape replaced the whole state on every run, dropping the
            # dedup cursor and silently re-ingesting unchanged payloads.
            current_state = self.helper.get_state() or {}
            if "last_run" not in current_state:
                current_state = {**current_state, "last_run": now_iso}
                self.helper.set_state(current_state)
            self.helper.connector_logger.info(
                "Get IOC since " + current_state["last_run"]
            )
            # ``opencti_bundle`` now re-raises on bundle-build / send
            # failure so the ``except`` below can flag the work as
            # in-error AND skip the ``last_run`` advance — the
            # previous swallow-and-log shape silently advanced state
            # on failed runs, hiding the failure from operators and
            # from the platform's connector-health monitor while
            # still letting the next run skip the un-ingested
            # payload as "already seen" (via ``last_run``).
            self.opencti_bundle(work_id)
            current_state = self.helper.get_state() or {}
            self.helper.set_state({**current_state, "last_run": now_iso})
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)
            # NOTE: interval sleeping is handled by the outer ``run()`` loop
            # in units of hours; sleeping here for ``self.beaconbeagle_interval``
            # *seconds* would add an extra (and confusingly short) pause every
            # cycle and would also block ``run-and-terminate`` mode from
            # exiting promptly.
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            error_message = f"BeaconBeagle run failed: {e}"
            self.helper.connector_logger.error(error_message)
            # Mark the work as failed on the platform so it shows up
            # red in the connector-status UI and the platform's
            # heartbeat / alerting can trigger. Best-effort — if
            # ``work_id`` is ``None`` (initiate_work itself failed)
            # there is nothing to flag, and the secondary
            # ``to_processed`` call is wrapped so any platform-side
            # error doesn't mask the original exception in the log.
            if work_id is not None:
                try:
                    self.helper.api.work.to_processed(
                        work_id, error_message, in_error=True
                    )
                except Exception as flag_err:
                    self.helper.connector_logger.error(
                        f"Failed to mark work {work_id} as in_error: {flag_err}"
                    )

    def run(self):
        self.helper.connector_logger.info("Fetching BeaconBeagle datasets...")
        self.set_marking()
        # Delegate scheduling to the helper rather than a manual
        # ``while True`` / ``time.sleep`` loop (linter rule VC314).
        # ``schedule_process`` runs ``process_data`` immediately, re-runs it
        # every ``duration_period`` seconds with automatic queue
        # backpressure, and transparently handles run-and-terminate mode
        # (single run, then ping + exit).
        self.helper.schedule_process(
            message_callback=self.process_data,
            duration_period=self.beaconbeagle_interval * 60 * 60,
        )


if __name__ == "__main__":
    # Match the connector-template entrypoint convention
    # (``templates/external-import/src/main.py:16-24``): print the full
    # traceback to stderr and exit non-zero on any unhandled exception,
    # so Docker / Kubernetes restart policies and the platform's
    # connector-health checks see the crash for what it is. The previous
    # shape (``print(e)`` + ``time.sleep(10)`` + ``sys.exit(0)``) hid the
    # stack trace, masked the failure as "successful exit" to the
    # orchestrator, and added a confusing ten-second pause that delayed
    # restarts without helping diagnose anything.
    try:
        BeaconBeagleConnector = BeaconBeagle()
        BeaconBeagleConnector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
