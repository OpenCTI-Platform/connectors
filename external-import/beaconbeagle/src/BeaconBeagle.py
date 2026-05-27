import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time

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


def _stix_pattern_escape(value):
    """Escape a string for safe inclusion inside a STIX 2.1 single-quoted literal.

    STIX 2.1 string constants require ``\\`` and ``'`` to be escaped
    inside ``'...'`` literals. Values like URLs or User-Agent strings
    routinely contain those characters; interpolating them raw produces
    invalid patterns and non-deterministic indicator IDs.
    """
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


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
        # links_duration: hours used as the fallback relationship
        # window when BeaconBeagle does not provide a ``lasttime`` for a
        # given C2 entry. The fallback is wired into
        # ``beaconbeagle_api_get_list`` below — the previous shape loaded
        # this config but never consulted it, so operators changing the
        # value got no effect.
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

    def beaconbeagle_api_get_list(self):
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
                return {}
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
                return {}
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
                    C2_key = "None"
                try:
                    # ``datetime`` is imported as the module (``import datetime``),
                    # so ``fromtimestamp`` lives on ``datetime.datetime``, not on
                    # the module itself.
                    C2_Firsttime = datetime.datetime.fromtimestamp(one_C2["Firsttime"])
                except Exception as inst:
                    C2_Firsttime = datetime.datetime.now()
                    self.helper.connector_logger.debug(
                        f"Reading 'Firsttime' error: {str(inst)}"
                    )
                try:
                    C2_lasttime = datetime.datetime.fromtimestamp(one_C2["lasttime"])
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'lasttime' error: {str(inst)}"
                    )
                    # Honour ``BEACONBEAGLE_LINKS_DURATION`` as the
                    # documented fallback window when the BeaconBeagle
                    # payload omits ``lasttime`` — the relationships
                    # downstream get a bounded ``stop_time = start_time +
                    # links_duration`` instead of an arbitrary ``now()``
                    # that would silently expand every relationship's
                    # validity window past the operator's configured limit.
                    fallback_start = (
                        C2_Firsttime
                        if C2_Firsttime is not None
                        else datetime.datetime.now()
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
                try:
                    C2_asn = one_C2["asn"]
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'asn' error: {str(inst)}"
                    )
                    C2_asn = 0
                try:
                    C2_asn_org = one_C2["asn_org"]
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'asn_org' error: {str(inst)}"
                    )
                    C2_asn_org = ""
                try:
                    C2_country = one_C2["country"]
                except Exception as inst:
                    self.helper.connector_logger.debug(
                        f"Reading 'country' error: {str(inst)}"
                    )
                    C2_country = ""

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
                                        hash = one_seenin["config_hash"]
                                        try:
                                            url_config = f"https://beaconbeagle.com/api/v1/configs/{hash}"
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
                                                f" No way to retreive config {hash}  ({str(inst)})."
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
        return {}

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
        """Run ``whois -h bgp.tools -v <ip>`` and parse the data line into a dict."""
        try:
            # ``-v`` and the IP must be passed as separate ``subprocess`` argv
            # entries. The previous shape concatenated them into a single
            # argument with a leading space, which ``whois`` parses as an
            # unknown query string and rejects.
            cmd = ["whois", "-h", "bgp.tools", "-v", str(ip_to_check)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

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
            # ``whois`` binary not in the container — surface a distinct
            # sentinel so the caller can disable BGP lookups gracefully
            # without crashing the run.
            self.helper.connector_logger.error(
                "`whois` command not found in PATH — install the `whois` "
                "package in the image or disable BEACONBEAGLE_SEARCH_BGPAS."
            )
            return "Process error"
        except (subprocess.CalledProcessError, StopIteration, IndexError):
            return "Process error"
        except Exception as e:
            self.helper.connector_logger.error(
                f"Unexpected error during whois lookup for {ip_to_check}: {e}"
            )
            return "Unknown error"

    def get_type_pure_regex(self, text):
        text = text.strip()

        # Dictionnaire des motifs (Patterns)
        patterns = {
            # IPv4 : 4 groupes de 1 à 3 chiffres séparés par des points
            "IPv4": r"^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            # IPv6 : Format simplifié (8 groupes de hexa séparés par :) ou formats compressés ::
            "IPv6": r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$",
            # Hashes (Hexadécimal strict)
            "MD5": r"^[a-fA-F0-9]{32}$",
            "SHA256": r"^[a-fA-F0-9]{64}$",
            "SHA512": r"^[a-fA-F0-9]{128}$",
            # Domain : Lettres/chiffres/tirets, se terminant par une extension de 2+ lettres
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
            + datetime.datetime.now().strftime("%Y-%m-%d")
            + ".  \n"
        )
        description += "All informations:  \n"

        description += self.DictToText(target, "  \n")

        if start_time is None:
            try:
                start_time = datetime.datetime.fromisoformat(
                    str(target.get("Firsttime"))
                ).replace(tzinfo=datetime.timezone.utc)
            except Exception as inst:
                self.helper.connector_logger.error(
                    f"Error while parsing Firsttime for start_time, we set it to None ({str(inst)})."
                )

        if stop_time is None:
            try:
                stop_time = datetime.datetime.fromisoformat(
                    str(target.get("lasttime"))
                ).replace(tzinfo=datetime.timezone.utc)
            except Exception as inst:
                self.helper.connector_logger.error(
                    f"Error while parsing lasttime for stop_time, we set it to None ({str(inst)})."
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

            # We have to deal with case key is a domain
            if not target["key"] == target["ip"]:
                # we have a domain to add
                domain = target["key"]
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

            # IF requested, we make a BGP Whois lookup to get more infos for ASN and Country
            if self.beaconbeagle_search_bgpas:
                try:
                    if str(target["asn"]) == "None" or str(target["Country"]) == "None":
                        self.helper.connector_logger.debug(
                            f"     > Infos does not include AS ou Country, Whois bgp tool for {target["ip"]}"
                        )
                        whoisdata = self.get_infos_whois(target["ip"])
                        if "Process error" in str(whoisdata):
                            self.helper.connector_logger.error(
                                f"     > Whois bgp tool said ouch {whoisdata}"
                            )
                        elif "Unknown error" in str(whoisdata):
                            self.helper.connector_logger.error(
                                f"     > Whois bgp tool said ouch unknown err {whoisdata}"
                            )
                        else:
                            self.helper.connector_logger.debug(
                                f"     > Whois bgp tool said {whoisdata}"
                            )
                            if not whoisdata["asn"] is None:
                                target["asn"] = whoisdata["asn"]
                            if not whoisdata["as_org"] is None:
                                target["as_org"] = whoisdata["as_org"]
                            if not whoisdata["country"] is None:
                                target["Country"] = whoisdata["country"]
                        del whoisdata
                except Exception as inst:
                    self.helper.connector_logger.error(
                        f"Error no way to make whois bgp for {target['ip']} with error {inst}"
                    )

            if self.beaconbeagle_link_country:
                try:
                    if str(target["Country"]) == "None":
                        self.helper.connector_logger.warning(
                            f"     > Target IP's Country is {target["Country"]}, we skip this one."
                        )
                    else:
                        self.helper.connector_logger.debug(
                            f"     > Target IP is in {target["Country"]}, linking country."
                        )
                        # ``pycti.Location.generate_id`` expects
                        # ``(name, location_type)``; passing a STIX
                        # pattern string here would produce unstable IDs
                        # and break Location deduplication across runs.
                        country_host = stix2.Location(
                            id=Location.generate_id(target["Country"], "Country"),
                            country=target["Country"],
                            custom_properties={
                                "x_opencti_score": 50,
                            },
                        )
                        self.helper.connector_logger.debug(
                            f"     > Target TLD {target["Country"]} is {country_host['country']}."
                        )
                        # STIX: StixCoreRelationship country --> IP
                        self.helper.connector_logger.debug(
                            f"    [+] StixCoreRelationship creation between Country and IP ({country_host['country']} > {observable_ip["value"]})."
                        )
                        relation_TC = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                country_host["id"],
                                observable_ip["id"],
                                start_time=start_time,
                                stop_time=stop_time,
                            ),
                            source_ref=country_host["id"],
                            target_ref=observable_ip["id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            stop_time=stop_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_score": 50,
                                "x_opencti_labels": ["BeaconBeagle"],
                            },
                            description=f"Has hosted a CobaltStrike between {start_time} and {stop_time}. (Link IPCountry)",
                        )
                        stix_objects.append(country_host)
                        stix_objects.append(relation_TC)
                        del country_host, relation_TC
                except Exception as inst:
                    self.helper.connector_logger.error(
                        f"Error no way to link country for {target['ip']} with error {inst}"
                    )

            if self.beaconbeagle_link_bgpas:
                if str(target["asn"]) == "None":
                    self.helper.connector_logger.warning(
                        f"     > Target IP's ASN is {target["asn"]}, we skip this one."
                    )
                else:
                    try:
                        self.helper.connector_logger.debug(
                            f"     > Target IP is in AS {target["asn"]} {target["as_org"]}, linking AS BGP."
                        )
                        description_as = f"This AS {target["asn"]} {target["as_org"]} was hosting a {self.beaconbeagle_link_tool} Configuration at {ip_add}"
                        as_stix = stix2.AutonomousSystem(
                            number=int(target["asn"]),
                            name=target["as_org"],
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
                            f"    [+] StixCoreRelationship creation between AS BGP and IP ({as_stix['number']} > {observable_ip["value"]})."
                        )
                        relation_TAS = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                as_stix["id"],
                                observable_ip["id"],
                                start_time=start_time,
                                stop_time=stop_time,
                            ),
                            source_ref=as_stix["id"],
                            target_ref=observable_ip["id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            stop_time=stop_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_score": 50,
                                "x_opencti_labels": ["BeaconBeagle"],
                            },
                            description=f"Has hosted a CobaltStrike between {start_time} and {stop_time}. (Link IP AS)",
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
                indicator_ip = stix2.Indicator(
                    id=Indicator.generate_id(ip_pattern),
                    name=ip_add,
                    pattern=ip_pattern,
                    pattern_type="stix",
                    description=description,
                    created_by_ref=identity_id,
                    created=start_time,
                    modified=stop_time,
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
            # We create URLs Observables if any
            try:
                if not None is target:
                    if target.get("FullData"):
                        if not None is target.get("FullData"):
                            if target.get("FullData").get("URLs"):
                                for one_url in target.get("FullData").get("URLs"):
                                    description_url = f"This URL was used by {self.beaconbeagle_link_tool} on {ip_add}"
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
                                    indicator_url = stix2.Indicator(
                                        id=Indicator.generate_id(_url_pattern),
                                        name=one_url,
                                        pattern=_url_pattern,
                                        pattern_type="stix",
                                        description=description,
                                        created_by_ref=identity_id,
                                        created=start_time,
                                        modified=stop_time,
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
                        indicator_ua = stix2.Indicator(
                            id=Indicator.generate_id(_ua_pattern),
                            name=UserAgent,
                            pattern=_ua_pattern,
                            pattern_type="stix",
                            description=description_ua,
                            created_by_ref=identity_id,
                            created=start_time,
                            modified=stop_time,
                            # confidence=60,
                            object_marking_refs=[self.beaconbeagle_marking],
                            custom_properties={
                                "x_opencti_score": 60,
                                "x_opencti_description": description_ua,
                                "x_opencti_main_observable_type": "Software",
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
                                    # # Using STIX2 Process creation
                                    process_stix = stix2.Process(
                                        object_marking_refs=[self.beaconbeagle_marking],
                                        cwd=process,
                                        pid=0,
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
                                    # process_stix_id = "process--"+str(process_stix["id"])
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
                                    indicator_proc = stix2.Indicator(
                                        id=Indicator.generate_id(_proc_pattern),
                                        name=f"Spawned process by {self.beaconbeagle_link_tool}",
                                        description=description_process,
                                        pattern_type="stix",
                                        pattern=_proc_pattern,
                                        indicator_types=["malicious-activity"],
                                        created_by_ref=identity_id,
                                        valid_from=start_time,
                                        # created=target['Firsttime'],
                                        # modified=target['lasttime'],
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
                                f" [+] StixCoreRelationship creation between MasterObservable and Observable ({master_observable_id} > {observable_l["standard_id"]})."
                            )
                            relation_OO = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to",
                                    master_observable_id,
                                    observable_l["standard_id"],
                                    start_time=start_time,
                                    stop_time=stop_time,
                                ),
                                source_ref=master_observable_id,
                                target_ref=observable_l["standard_id"],
                                relationship_type="related-to",
                                created_by_ref=identity_id,
                                start_time=start_time,
                                stop_time=stop_time,
                                object_marking_refs=[self.beaconbeagle_marking],
                                description=f"Link between IP and {observable_l['entity_type']} at {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")}. (Link )",
                            )
                            stix_objects.append(relation_OO)
                            del relation_OO
                        else:
                            self.helper.connector_logger.debug(
                                f" [+] StixCoreRelationship creation between MasterObservable and Observable ({master_observable_id} > {observable_l["id"]})."
                            )
                            relation_OO = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to",
                                    master_observable_id,
                                    observable_l["id"],
                                    start_time=start_time,
                                    stop_time=stop_time,
                                ),
                                source_ref=master_observable_id,
                                target_ref=observable_l["id"],
                                relationship_type="related-to",
                                created_by_ref=identity_id,
                                start_time=start_time,
                                stop_time=stop_time,
                                object_marking_refs=[self.beaconbeagle_marking],
                                description=f"Link between IP and {observable_l['type']} at {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")}. (Link )",
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
                            f"    [+] StixCoreRelationship creation between Tool and Observable ({self.beaconbeagle_link_tool} > {observable["standard_id"]})."
                        )
                        relation_OT = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                self.beaconbeagle_link_tool_id,
                                observable["standard_id"],
                                start_time=start_time,
                                stop_time=stop_time,
                            ),
                            source_ref=self.beaconbeagle_link_tool_id,
                            target_ref=observable["standard_id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            stop_time=stop_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            description=f"Was used by {self.beaconbeagle_link_tool} between {start_time} and {stop_time}. (Link ObsTool)",
                        )
                        stix_objects.append(relation_OT)
                        del relation_OT
                    else:
                        self.helper.connector_logger.debug(
                            f"    [+] StixCoreRelationship creation between Tool and Observable ({self.beaconbeagle_link_tool} > {observable["id"]})."
                        )
                        relation_OT = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                self.beaconbeagle_link_tool_id,
                                observable["id"],
                                start_time=start_time,
                                stop_time=stop_time,
                            ),
                            source_ref=self.beaconbeagle_link_tool_id,
                            target_ref=observable["id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            stop_time=stop_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            description=f"Was used by {self.beaconbeagle_link_tool} between {start_time} and {stop_time}. (Link ObsTool)",
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
                            f"    [+] StixCoreRelationship creation between Attack-Pattern and Observable ({self.beaconbeagle_link_ap} > {observable["standard_id"]})."
                        )
                        relation_OAP = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                self.beaconbeagle_link_ap_id,
                                observable["standard_id"],
                                start_time=start_time,
                                stop_time=stop_time,
                            ),
                            source_ref=self.beaconbeagle_link_ap_id,
                            target_ref=observable["standard_id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            stop_time=stop_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            description=f"Was used by {self.beaconbeagle_link_ap} between {start_time} and {stop_time}. (Link ObsAttackPattern)",
                        )
                        stix_objects.append(relation_OAP)
                        del relation_OAP
                    else:
                        self.helper.connector_logger.debug(
                            f"    [+] StixCoreRelationship creation between Attack-Pattern and Observable ({self.beaconbeagle_link_ap} > {observable["id"]})."
                        )
                        relation_OAP = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to",
                                self.beaconbeagle_link_ap_id,
                                observable["id"],
                                start_time=start_time,
                                stop_time=stop_time,
                            ),
                            source_ref=self.beaconbeagle_link_ap_id,
                            target_ref=observable["id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            stop_time=stop_time,
                            object_marking_refs=[self.beaconbeagle_marking],
                            description=f"Was used by {self.beaconbeagle_link_ap} between {start_time} and {stop_time}. (Link ObsAttackPattern)",
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

        # Create the Identity for BeaconBeagle Import
        identity_id = Identity.generate_id(
            name="BeaconBeagle", identity_class="organization"
        )
        identity = stix2.Identity(
            id=identity_id,
            spec_version="2.1",
            name="BeaconBeagle",
            # confidence=60,
            created="2026-01-01T00:00:00.000Z",
            modified="2026-01-01T00:00:00.000Z",
            identity_class="organization",
            type="identity",
            # ``object_marking_refs`` must be a list of marking-definition
            # refs/objects per STIX 2.1; the bare ``stix2.TLP_WHITE``
            # shape was accepted by some validators but rejected by
            # others and would have intermittently broken serialization.
            object_marking_refs=[stix2.TLP_WHITE],
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
                ddos_attack = stix2.AttackPattern(
                    id=AttackPattern.generate_id(_ap_name, _ap_mitre_id),
                    name=_ap_name,
                    description=(
                        f"Attack pattern linked to {self.beaconbeagle_link_tool} "
                        "traffic seen by BeaconBeagle."
                    ),
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
        # Reset the pending dedup hash so a previous run's value can
        # never accidentally be committed against a payload it did not
        # describe (e.g. if the next ``beaconbeagle_api_get_list`` call
        # short-circuits on an empty payload).
        self._pending_payload_hash = None
        targeted = self.beaconbeagle_api_get_list()
        if targeted is None:
            self.helper.connector_logger.info(
                "No data retrieved from BeaconBeagle API (None), skipping bundle creation."
            )
        elif len(targeted) == 0:
            self.helper.connector_logger.info(
                "No data retrieved from BeaconBeagle API (empty), skipping bundle creation."
            )
        else:
            try:
                stix_bundle = self.create_stix_bundle(targeted)
                # ``Bundle.serialize()`` already returns a valid STIX 2.1
                # JSON string. The previous ``json.loads`` /
                # ``json.dumps(..., indent=4)`` round-trip multiplied the
                # CPU + memory cost on every send (potentially hundreds of
                # MB for a busy BeaconBeagle payload) without changing
                # what the worker actually ingests.
                serialized_bundle = stix_bundle.serialize()
                self.helper.send_stix2_bundle(serialized_bundle, work_id=work_id)
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
            except Exception as e:
                self.helper.connector_logger.error(str(e))

    def send_bundle(self, work_id, serialized_bundle: str):
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.connector_logger.error(f"Error while sending bundle: {e}")

    def process_data(self):
        try:
            self.helper.connector_logger.info("Synchronizing with BeaconBeagle APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            friendly_name = "BeaconBeagle run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
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
                current_state = {
                    **current_state,
                    "last_run": str(now.strftime("%Y-%m-%d %H:%M:%S")),
                }
                self.helper.set_state(current_state)
            self.helper.connector_logger.info(
                "Get IOC since " + current_state["last_run"]
            )
            self.opencti_bundle(work_id)
            current_state = self.helper.get_state() or {}
            self.helper.set_state(
                {**current_state, "last_run": now.astimezone().isoformat()}
            )
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
            self.helper.connector_logger.error(str(e))

    def run(self):
        self.helper.connector_logger.info("Fetching BeaconBeagle datasets...")
        self.set_marking()
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.beaconbeagle_interval * 60 * 60)


if __name__ == "__main__":
    try:
        BeaconBeagleConnector = BeaconBeagle()
        BeaconBeagleConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
