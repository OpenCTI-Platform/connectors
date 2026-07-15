/home/paulineeustachy/code/filigran/connectors-worktrees/6848-rst-threat-feed/external-import/rst-threat-feed/src/rstcloud/connector.py.tmp
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import List

import stix2
from pycti import Identity, OpenCTIConnectorHelper, StixCoreRelationship

from rstcloud.FeedFetch import Downloader
from rstcloud.MitreTtpDownloader import MitreTtpDownloader
from rstcloud.common import FeedType, ThreatTypes, feed_converter
from rstcloud.settings import ConnectorSettings


class RSTThreatFeed:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        # Schedule / interval
        self.interval = int(self.config.rst_threat_feed.interval)

        # Downloader configuration (used by FeedFetch.Downloader)
        self._downloader_config = {
            "baseurl": self.config.rst_threat_feed.baseurl,
            "apikey": self.config.rst_threat_feed.apikey.get_secret_value(),
            "contimeout": int(self.config.rst_threat_feed.contimeout),
            "readtimeout": int(self.config.rst_threat_feed.readtimeout),
            "retry": int(self.config.rst_threat_feed.retry),
            "ssl_verify": bool(self.config.rst_threat_feed.ssl_verify),
            "latest": str(self.config.rst_threat_feed.latest),
            "time_range": ["day", "1h", "4h", "12h"],
            "feeds": {
                "filetype": "json",
                "ioctype": {
                    "ip": bool(self.config.rst_threat_feed.ip),
                    "domain": bool(self.config.rst_threat_feed.domain),
                    "url": bool(self.config.rst_threat_feed.url),
                    "hash": bool(self.config.rst_threat_feed.hash),
                },
            },
        }

        # Import / scoring / behavior
        self._min_score_import = int(self.config.rst_threat_feed.min_score_import)
        self._min_score_detection = {
            "IPv4-Addr": int(self.config.rst_threat_feed.min_score_detection_ip),
            "Domain-Name": int(self.config.rst_threat_feed.min_score_detection_domain),
            "Url": int(self.config.rst_threat_feed.min_score_detection_url),
            "StixFile": int(self.config.rst_threat_feed.min_score_detection_hash),
        }
        self._only_new = bool(self.config.rst_threat_feed.only_new)
        self._only_attributed = bool(self.config.rst_threat_feed.only_attributed)
        self._keep_named_vulns = bool(self.config.rst_threat_feed.keep_named_vulns)
        self._create_custom_ttps = bool(self.config.rst_threat_feed.create_custom_ttps)
        self._create_mitre_ttps = bool(self.config.rst_threat_feed.create_mitre_ttps)

        # As requested by instructions
        self.update_existing_data = False

        # MITRE mapping helper
        self.mitre_downloader = MitreTtpDownloader(self.config)
        self.mitre_ttp_mapping = self.mitre_downloader.load_ttp_mapping()

        # Upload retry settings
        self._max_retries = int(self.config.rst_threat_feed.max_retries)
        self._retry_delay = int(self.config.rst_threat_feed.retry_delay)
        self._retry_backoff_multiplier = float(
            self.config.rst_threat_feed.retry_backoff_multiplier
        )

        if self._downloader_config["latest"] not in self._downloader_config["time_range"]:
            raise ValueError(
                "Incorrect time range. Use one of "
                f"{self._downloader_config['time_range']}"
            )

    def get_interval(self) -> int:
        return int(self.interval)

    def feed_enabled(self, ioc_type: str) -> bool:
        config = self._downloader_config
        if "feeds" in config and "ioctype" in config["feeds"]:
            feed_types = [FeedType.IP, FeedType.DOMAIN, FeedType.URL, FeedType.HASH]
            if ioc_type not in feed_types:
                raise ValueError(f"Only {feed_types} values supported")
            elif ioc_type in config["feeds"]["ioctype"]:
                return config["feeds"]["ioctype"][ioc_type]
            else:
                return True
        else:
            return True

    def run(self):
        self.helper.log_info("Starting RST Threat Feed connector")
        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    last_run_str = datetime.fromtimestamp(
                        last_run, tz=timezone.utc
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    self.helper.log_info(f"Connector's last run: {last_run_str}")
                else:
                    last_run = None
                    self.helper.log_info("Connector's first run")

                if last_run is None or timestamp - last_run > self.get_interval():
                    try:
                        self.mitre_downloader.download_mitre_ttps()
                        self.mitre_ttp_mapping = self.mitre_downloader.load_ttp_mapping()
                    except Exception as ex:
                        self.helper.log_error(f"Failed to update MITRE TTP mappings: {ex}")

                    for ioc_feed_type in [
                        FeedType.IP,
                        FeedType.DOMAIN,
                        FeedType.URL,
                        FeedType.HASH,
                    ]:
                        if self.feed_enabled(ioc_feed_type):
                            self._process_feed(ioc_feed_type)

                    self.helper.set_state({"last_run": timestamp})
                else:
                    new_interval = round(self.get_interval() - (timestamp - last_run), 2)
                    self.helper.log_info(
                        f"Connector will not run. Next run in: {new_interval} seconds."
                    )
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stopped")
                sys.exit(0)
            except Exception as ex:
                self.helper.log_error(str(ex))
                raise

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stopped")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)

    def _process_feed(self, feed_type):
        try:
            downloader = Downloader(self._downloader_config)
            result = downloader.get_feed(feed_type)
            if result["status"] == "ok":
                file_path = result["message"]
                stix_bundle = self._create_stix_bundle(file_path, feed_type)
                self._batch_send(stix_bundle, feed_type)
                if os.path.exists(file_path):
                    os.remove(file_path)
            else:
                self.helper.log_error(f"Failed to download {feed_type} feed: {result}")
        except Exception as ex:
            self.helper.log_error(f"Error processing {feed_type} feed. Error: {ex}")

    def _create_stix_bundle(self, filepath, feed_type):
        self.helper.log_info(f"Parsing IOCs from {filepath}")
        iocs, threats, mapping = feed_converter(
            filepath,
            feed_type,
            self._min_score_import,
            self._only_new,
            self._only_attributed,
            self._keep_named_vulns,
            self._create_mitre_ttps,
            self._create_custom_ttps,
            self.mitre_ttp_mapping,
        )
        self.helper.log_info(
            f"Parsed IOCs: {len(iocs)}, Threats: {len(threats)}, Mappings: {len(mapping)}"
        )

        stix_bundle = list()

        organization = stix2.v21.Identity(
            id=Identity.generate_id("RST Cloud", "organization"),
            name="RST Cloud",
            identity_class="organization",
            description="Threat Intelligence Company https://www.rstcloud.com",
        )
        stix_bundle.append(organization)

        self.helper.log_info(f"Converting {len(iocs)} IOCs to STIX objects")
        for ioc_id, ioc in iocs.items():
            external_references = []
            for i in ioc["src"]:
                external_references.append(
                    stix2.v21.ExternalReference(source_name=i["name"], url=i["url"])
                )

            x_opencti_detection = False
            try:
                if int(ioc["score"]) > int(self._min_score_detection[ioc["observable_type"]]):
                    x_opencti_detection = True
            except Exception as ex:
                self.helper.log_info(
                    f"Error while checking x_opencti_detection for {ioc['name']}. {ex}"
                )

            indicator = stix2.v21.Indicator(
                id=ioc_id,
                name=ioc["name"],
                description=ioc["descr"],
                labels=ioc["tags"] + ioc["threats"],
                pattern_type="stix",
                pattern=ioc["pattern"],
                valid_from=ioc["lseen"],
                created=ioc["fseen"],
                modified=ioc["collect"],
                created_by_ref=organization.id,
                object_marking_refs=[stix2.TLP_WHITE],
                confidence=int(ioc["confidence"]),
                external_references=external_references,
                custom_properties={
                    "x_opencti_score": ioc["score"],
                    "x_opencti_main_observable_type": ioc["observable_type"],
                    "x_opencti_detection": x_opencti_detection,
                },
            )
            stix_bundle.append(indicator)

        self.helper.log_info(f"Converting {len(threats)} Threats to STIX objects")
        for threat_key, threat in threats.items():
            external_references = []
            for source_name, source_url in threat["src"].items():
                external_references.append(
                    stix2.v21.ExternalReference(source_name=source_name, url=source_url)
                )

            threat_object = None
            isfamily = True if "/" not in threat["name"] else False

            shared_parameters = {
                "id": threat_key,
                "name": threat["name"],
                "created_by_ref": organization.id,
                "external_references": external_references,
            }
            if "aliases" in threat:
                shared_parameters["aliases"] = threat["aliases"]

            malware_parameters = shared_parameters.copy()
            malware_parameters["is_family"] = isfamily

            if threat["type"] == ThreatTypes.MALWARE:
                threat_object = stix2.v21.Malware(**malware_parameters)
            elif threat["type"] == ThreatTypes.RANSOMWARE:
                threat_object = stix2.v21.Malware(
                    malware_types=["ransomware"], **malware_parameters
                )
            elif threat["type"] == ThreatTypes.BACKDOOR:
                threat_object = stix2.v21.Malware(
                    malware_types=["backdoor"], **malware_parameters
                )
            elif threat["type"] == ThreatTypes.RAT:
                threat_object = stix2.v21.Malware(
                    malware_types=["remote-access-trojan"], **malware_parameters
                )
            elif threat["type"] == ThreatTypes.EXPLOIT:
                threat_object = stix2.v21.Malware(
                    malware_types=["exploit-kit"], **malware_parameters
                )
            elif threat["type"] == ThreatTypes.CRYPTOMINER:
                threat_object = stix2.v21.Malware(
                    malware_types=["resource-exploitation"], **malware_parameters
                )
            elif threat["type"] == ThreatTypes.GROUP:
                threat_object = stix2.v21.IntrusionSet(**shared_parameters)
            elif threat["type"] == ThreatTypes.CAMPAIGN:
                threat_object = stix2.v21.Campaign(**shared_parameters)
            elif threat["type"] == ThreatTypes.TOOL:
                threat_object = stix2.v21.Tool(**shared_parameters)
            elif threat["type"] == ThreatTypes.TTP:
                if "mitre_id" not in threat and self._create_custom_ttps:
                    threat_object = stix2.v21.AttackPattern(**shared_parameters)
                elif "mitre_id" in threat and self._create_mitre_ttps:
                    threat_object = stix2.v21.AttackPattern(
                        id=threat_key,
                        name=threat["name"],
                        custom_properties={"x_mitre_id": threat["mitre_id"]},
                        allow_custom=True,
                    )
            elif threat["type"] == ThreatTypes.VULNERABILITY:
                if "aliases" in threat:
                    shared_parameters["allow_custom"] = True
                    shared_parameters["custom_properties"] = {
                        "x_opencti_aliases": threat["aliases"]
                    }
                else:
                    cve_id = threat["name"].upper()
                    external_references = [
                        stix2.v21.ExternalReference(
                            source_name="cve.org",
                            external_id=cve_id,
                            url=f"https://www.cve.org/CVERecord?id={cve_id}",
                        )
                    ]
                    shared_parameters["external_references"] = external_references

                shared_parameters.pop("aliases", None)
                threat_object = stix2.v21.Vulnerability(**shared_parameters)

            if threat_object:
                stix_bundle.append(threat_object)

        self.helper.log_info(f"Converting {len(mapping)} Relations to STIX objects")
        for m in mapping:
            indicator_id = m[0]
            threat_id = m[1]
            fseen = m[2]
            collect = m[3]
            refs = m[4]

            external_references = []
            for i in refs:
                external_references.append(
                    stix2.v21.ExternalReference(source_name=i["name"], url=i["url"])
                )

            relationship_type = "indicates"
            if threats[threat_id]["type"] == "sector":
                relationship_type = "related-to"

            if fseen > collect + timedelta(0, 3):
                self.helper.log_error(
                    f"stop_time {collect} must be later than start_time {fseen}. Fixing"
                )
                fseen = collect

            relation = stix2.v21.Relationship(
                id=StixCoreRelationship.generate_id(
                    relationship_type, indicator_id, threat_id, collect, collect
                ),
                source_ref=indicator_id,
                target_ref=threat_id,
                relationship_type=relationship_type,
                start_time=fseen,
                stop_time=collect + timedelta(0, 3),
                description=f"IOC associated with: {threats[threat_id]['name']}",
                created_by_ref=organization.id,
                object_marking_refs=[stix2.TLP_WHITE],
                created=collect,
                modified=collect,
                external_references=external_references,
                allow_custom=True,
            )
            stix_bundle.append(relation)

        return stix_bundle

    def _batch_send(self, stix_bundle: List, feed_type: str):
        timestamp = int(time.time())
        now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        friendly_name = f"Run for {feed_type} @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
        self.helper.log_debug(f"Start uploading of the objects: {len(stix_bundle)}")

        max_retries = self._max_retries
        retry_delay = self._retry_delay

        for attempt in range(max_retries):
            try:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                bundle = stix2.v21.Bundle(objects=stix_bundle, allow_custom=True)
                self.helper.send_stix2_bundle(
                    bundle=bundle.serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
                self.helper.log_info(
                    f"Connector ran successfully, saving last_run as {str(timestamp)}"
                )
                message = f"Last_run stored, next run in: {str(self.get_interval())} seconds"
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_debug("End of the batch upload")
                return
            except (ConnectionError, OSError, TimeoutError) as ex:
                error_message = (
                    f"Communication issue with opencti (attempt {attempt + 1}/{max_retries}): {ex}"
                )
                self.helper.log_error(error_message)
                if attempt < max_retries - 1:
                    self.helper.log_info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= self._retry_backoff_multiplier
                else:
                    self.helper.log_error(
                        f"Failed to upload {feed_type} feed after {max_retries} attempts. Skipping this feed."
                    )
                    return
            except Exception as ex:
                error_message = f"Unexpected error during upload for {feed_type}: {ex}"
                self.helper.log_error(error_message)
                raise ConnectionError(error_message) from ex
