import os
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from typing import List

import stix2
import yaml
from pycti import (
    Identity,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from rstcloud import (
    FeedFetch,
    FeedType,
    ThreatTypes,
    feed_converter,
)


class RSTThreatFeed:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.safe_load(open(config_file_path, encoding="UTF-8"))
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.interval = self.get_config("interval", config, 86400)
        self._downloader_config = {
            "baseurl": self.get_config(
                "baseurl", config, "https://api.rstcloud.net/v1/"
            ),
            "apikey": self.get_config("apikey", config, None),
            "contimeout": int(self.get_config("contimeout", config, 30)),
            "readtimeout": int(self.get_config("readtimeout", config, 60)),
            "retry": int(self.get_config("retry", config, 5)),
            "ssl_verify": bool(self.get_config("ssl_verify", config, True)),
            "latest": str(self.get_config("latest", config, "day")),
            "time_range": ["day", "1h", "4h", "12h"],
            "feeds": {
                "filetype": "json",
                "ioctype": {
                    "ip": bool(self.get_config("ip", config, True)),
                    "domain": bool(self.get_config("domain", config, True)),
                    "url": bool(self.get_config("url", config, True)),
                    "hash": bool(self.get_config("hash", config, True)),
                },
            },
        }
        self._min_score_import = int(self.get_config("min_score_import", config, 20))
        self._min_score_detection = {
            "IPv4-Addr": self.get_config(
                "min_score_detection_ip",
                config,
                45,
            ),
            "Domain-Name": self.get_config(
                "min_score_detection_domain",
                config,
                45,
            ),
            "Url": self.get_config(
                "min_score_detection_url",
                config,
                45,
            ),
            "StixFile": self.get_config(
                "min_score_detection_hash",
                config,
                45,
            ),
        }
        self._only_new = bool(self.get_config("only_new", config, True))
        self._only_attributed = bool(self.get_config("only_attributed", config, True))
        self.update_existing_data = bool(
            get_config_variable(
                "CONNECTOR_UPDATE_EXISTING_DATA",
                ["connector", "update_existing_data"],
                config,
                default=True,
            )
        )
        if (
            self._downloader_config["latest"]
            not in self._downloader_config["time_range"]
        ):
            raise ValueError(
                f"Incorrect time range. Use one of {self._downloader_config['time_range']}"
            )

    @staticmethod
    def get_config(name: str, config, default=None):
        env_name = f"RST_THREAT_FEED_{name.upper()}"
        result = get_config_variable(env_name, ["rst-threat-feed", name], config)
        if result is not None:
            return result
        else:
            return default

    def get_interval(self) -> int:
        return int(self.interval)

    def feed_enabled(self, ioc_type: str) -> bool:
        config = self._downloader_config
        if "feeds" in config and "ioctype" in config["feeds"]:
            feed_types = [FeedType.IP, FeedType.DOMAIN, FeedType.URL, FeedType.HASH]
            if ioc_type not in feed_types:
                raise ValueError(f"Only {feed_types} values supported")
            else:
                if ioc_type in config["feeds"]["ioctype"]:
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

                if last_run is None or ((timestamp - last_run) > self.get_interval()):
                    for ioc_feed_type in [
                        FeedType.IP,
                        FeedType.DOMAIN,
                        FeedType.URL,
                        FeedType.HASH,
                    ]:
                        # if not specified all feeds are enabled by default
                        # a user can select what type of feed to consume
                        if self.feed_enabled(ioc_feed_type):
                            self._process_feed(ioc_feed_type)
                    self.helper.set_state({"last_run": timestamp})
                else:
                    new_interval = round(
                        self.get_interval() - (timestamp - last_run), 2
                    )
                    self.helper.log_info(
                        f"Connector will not run. Next run in: {new_interval} seconds."
                    )
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stopped")
                sys.exit(0)
            except Exception as ex:
                self.helper.log_error(str(ex))
                raise ex

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stopped")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)

    def _process_feed(self, feed_type):
        downloader = FeedFetch.Downloader(self._downloader_config)
        result = downloader.get_feed(feed_type)
        if result["status"] == "ok":
            stix_bundle = self._create_stix_bundle(result["message"], feed_type)
            self._batch_send(stix_bundle, feed_type)
        else:
            raise Exception(result)

    def _create_stix_bundle(self, filepath, feed_type):
        self.helper.log_info(f"Parsing IOCs from {filepath}")

        iocs, threats, mapping = feed_converter(
            filepath,
            feed_type,
            self._min_score_import,
            self._only_new,
            self._only_attributed,
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
            external_references = list()
            for i in ioc["src"]:
                external_references.append(
                    stix2.v21.ExternalReference(source_name=i["name"], url=i["url"])
                )
            x_opencti_detection = False
            try:
                if int(ioc["score"]) > int(
                    self._min_score_detection[ioc["observable_type"]]
                ):
                    x_opencti_detection = True
            except Exception as ex:
                self.helper.log_info(
                    f"Error while checking x_opencti_detection for {ioc['name']}. {ex}"
                )

            # indicator
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
            external_references = list()
            for source_name, source_url in threat["src"].items():
                external_references.append(
                    stix2.v21.ExternalReference(source_name=source_name, url=source_url)
                )

            malicious_object = None
            isfamily = True if "/" not in threat["name"] else False
            if threat["type"] == ThreatTypes.MALWARE:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.RANSOMWARE:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    malware_types=["ransomware"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.BACKDOOR:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    malware_types=["backdoor"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.RAT:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    malware_types=["remote-access-trojan"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.EXPLOIT:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    malware_types=["exploit-kit"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.CRYPTOMINER:
                malicious_object = stix2.v21.Malware(
                    id=threat_key,
                    is_family=isfamily,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    malware_types=["resource-exploitation"],
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.GROUP:
                malicious_object = stix2.v21.IntrusionSet(
                    id=threat_key,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.CAMPAIGN:
                malicious_object = stix2.v21.Campaign(
                    id=threat_key,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.TOOL:
                malicious_object = stix2.v21.Tool(
                    id=threat_key,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    external_references=external_references,
                )
            elif threat["type"] == ThreatTypes.VULNERABILITY:
                malicious_object = stix2.v21.Vulnerability(
                    id=threat_key,
                    name=threat["name"],
                    created_by_ref=organization.id,
                    external_references=[
                        stix2.v21.ExternalReference(
                            source_name="cve.org",
                            external_id=threat["name"].upper(),
                            url=f"https://www.cve.org/CVERecord?id={threat['name'].upper()}",
                        )
                    ],
                )
            if malicious_object:
                stix_bundle.append(malicious_object)

        self.helper.log_info(f"Converting {len(mapping)} Relations to STIX objects")
        for m in mapping:
            indicator_id = m[0]
            threat_id = m[1]
            fseen = m[2]
            collect = m[3]
            refs = m[4]

            external_references = list()
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
        except Exception as ex:
            error_message = f"Communication issue with opencti {ex}"
            self.helper.log_error(error_message)
            raise ConnectionError(error_message) from ex

        # Finish the work
        self.helper.log_info(
            f"Connector ran successfully, saving last_run as {str(timestamp)}"
        )
        message = f"Last_run stored, next run in: {str(self.get_interval())} seconds"
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_debug("End of the batch upload")


if __name__ == "__main__":
    try:
        connector = RSTThreatFeed()
        connector.run()
    except Exception as ex:
        print(str(ex))
        traceback.print_tb(ex.__traceback__)
        time.sleep(10)
        sys.exit(0)
