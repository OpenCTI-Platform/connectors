"""OpenCTI Malcore connector core module."""

import json
import ssl
import sys
import time
import urllib
from datetime import datetime, timezone
from urllib import parse

import stix2
from malcore.settings import ConnectorSettings
from pycti import (
    Identity,
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class Malcore:

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        # Connector SDK settings + helper (injected from main.py.tmp / tests)
        self.config = config
        self.helper = helper

        # Malcore-specific configuration
        self.api_url = self.config.malcore.api_url
        self.api_key = self.config.malcore.api_key.get_secret_value()
        self.score = self.config.malcore.score
        self.limit = self.config.malcore.limit
        self.interval = self.config.malcore.interval

        # In previous implementation it was pulled from CONNECTOR_UPDATE_EXISTING_DATA; per instructions keep it fixed.
        self.update_existing_data = False

        # Create identity in OpenCTI (executed at runtime; tests mock helper internals)
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Malcore",
            description="Malcore is a tool designed to simplify reverse engineering and malware analysis through simple file analysis.",
        )

    def get_interval(self):
        return int(self.interval) * 60 * 60

    def run_feed_ioc(self, timestamp):
        try:
            now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            friendly_name = "Malcore connector ioc run @ " + now.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            feed_type = "ioc"
            req = urllib.request.Request(self.api_url)
            req.add_header("apikey", self.api_key)
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", "Malcore/OpenCTI")
            req.method = "POST"
            body = parse.urlencode({"feed_type": feed_type}).encode()
            response = urllib.request.urlopen(
                req, context=ssl.create_default_context(), data=body
            )
            feed = response.read()
            data_json = json.loads(feed)
            malcore_org_id = Identity.generate_id("Malcore", "organization")
            identity = stix2.Identity(
                id=malcore_org_id, name="Malcore", identity_class="organization"
            )
            bundle_objects = []
            file_objects = []
            for item in data_json["data"]["data"]:
                key = next(iter(item))
                item_data = item[key]
                if "file_exif_data" in item_data:
                    hashes = item_data["hashes"]
                    upload_time = item_data["upload_time"]
                    file_exif_data = item_data["file_exif_data"]
                    file_extension = file_exif_data["file_information"][
                        "file_extension"
                    ]
                    mime_type = file_exif_data["mime_type"]
                    file_size = item_data["file_sizes"]["raw_byte_size"]
                    hashmd5 = hashes["md5"]
                    custom_properties = {"created_by_ref": malcore_org_id}
                    stix_file = stix2.File(
                        name=upload_time + file_extension,
                        hashes={
                            "MD5": hashmd5,
                            "SHA-1": hashes["sha1"],
                            "SHA-256": hashes["sha256"],
                        },
                        size=file_size,
                        mime_type=mime_type,
                        custom_properties=custom_properties,
                    )
                    file_objects.append(stix_file)
            bundle_objects.append(identity)
            bundle_objects.extend(file_objects)
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
            bundle_json = bundle.serialize()
            self.helper.send_stix2_bundle(
                bundle_json, update=self.update_existing_data, work_id=work_id
            )
            message = "IOC successfully run, storing last_run as " + str(timestamp)
            self.helper.log_info(message)
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
        except Exception as e:
            self.helper.log_error("IOC::" + str(e))

    def run_feed_threat(self, timestamp):
        try:
            now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            friendly_name = "Malcore connector threat run @ " + now.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            feed_type = "threat"
            req = urllib.request.Request(self.api_url)
            req.add_header("apikey", self.api_key)
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", "Malcore/OpenCTI")
            req.method = "POST"
            body = parse.urlencode({"feed_type": feed_type}).encode()
            response = urllib.request.urlopen(
                req, context=ssl.create_default_context(), data=body
            )
            feed = response.read()
            data_json = json.loads(feed)
            malcore_org_id = Identity.generate_id("Malcore", "organization")
            identity = stix2.Identity(
                id=malcore_org_id, name="Malcore", identity_class="organization"
            )
            bundle_objects = []
            external_reference = stix2.ExternalReference(
                source_name="Malcore database",
                url="https://app.malcore.io/",
                description="Malcore app URL",
            )
            indicators = []
            malware_objects = []
            relationships = []
            labels = ["threat"]
            for item in data_json["data"]["data"]:
                hash_value = item["hash"]
                score = item["score"]
                pattern = "[file:hashes.'SHA-256' = '" + hash_value + "']"
                stix_indicator = stix2.Indicator(
                    id=Indicator.generate_id(pattern),
                    name="Indicator: {}".format(hash_value),
                    description="Hash: {}".format(hash_value),
                    pattern_type="stix",
                    labels=labels,
                    pattern=pattern,
                    created_by_ref=malcore_org_id,
                    external_references=[external_reference],
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={"x_opencti_main_observable_type": "StixFile"},
                )
                indicators.append(stix_indicator)
                stix_malware = stix2.Malware(
                    id=Malware.generate_id(hash_value),
                    name="Malware: {}".format(hash_value),
                    description="Threat Tracked by Malcore",
                    is_family=False,
                    confidence=score,
                    created_by_ref=malcore_org_id,
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                malware_objects.append(stix_malware)
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates", stix_indicator.id, stix_malware.id
                    ),
                    source_ref=stix_indicator.id,
                    relationship_type="indicates",
                    target_ref=stix_malware.id,
                    confidence=score,
                    created_by_ref=malcore_org_id,
                )
                relationships.append(relationship)
            bundle_objects.append(identity)
            bundle_objects.extend(indicators)
            bundle_objects.extend(malware_objects)
            bundle_objects.extend(relationships)
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
            bundle_json = bundle.serialize()
            self.helper.send_stix2_bundle(
                bundle_json, update=self.update_existing_data, work_id=work_id
            )
            message = "Threat successfully run, storing last_run as " + str(timestamp)
            self.helper.log_info(message)
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
        except Exception as e:
            self.helper.log_error("THREAT::" + str(e))

    def run_feed_hash(self, timestamp):
        try:
            now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            friendly_name = "Malcore connector hash run @ " + now.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            feed_type = "hash"
            req = urllib.request.Request(self.api_url)
            req.add_header("apikey", self.api_key)
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", "Malcore/OpenCTI")
            req.method = "POST"
            body = parse.urlencode({"feed_type": feed_type}).encode()
            response = urllib.request.urlopen(
                req, context=ssl.create_default_context(), data=body
            )
            feed = response.read()
            data_json = json.loads(feed)
            bundle_objects = []
            malcore_org_id = Identity.generate_id("Malcore", "organization")
            identity = stix2.Identity(
                id=malcore_org_id, name="Malcore", identity_class="organization"
            )
            external_reference = stix2.ExternalReference(
                source_name="Malcore database",
                url="https://app.malcore.io/",
                description="Malcore app URL",
            )
            indicators = []
            for item in data_json["data"]["data"]:
                hash_value = item["hash"]
                pattern = "[file:hashes.'SHA-256' = '" + hash_value + "']"
                stix_indicator = stix2.Indicator(
                    id=Indicator.generate_id(hash_value),
                    pattern_type="stix",
                    pattern=pattern,
                    created_by_ref=malcore_org_id,
                    external_references=[external_reference],
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={"x_opencti_main_observable_type": "StixFile"},
                )
                indicators.append(stix_indicator)
            bundle_objects.append(identity)
            bundle_objects.extend(indicators)
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
            bundle_json = bundle.serialize()
            self.helper.send_stix2_bundle(
                bundle_json, update=self.update_existing_data, work_id=work_id
            )
            message = "Hash successfully run, storing last_run as " + str(timestamp)
            self.helper.log_info(message)
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
        except Exception as e:
            self.helper.log_error("HASH::" + str(e))

    def run(self):
        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.fromtimestamp(last_run, tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                if (
                    last_run is None
                    or timestamp - last_run > int(self.interval) * 60 * 60
                ):
                    self.helper.log_info("Connector will run!")
                    self.run_feed_ioc(timestamp)
                    self.run_feed_threat(timestamp)
                    self.run_feed_hash(timestamp)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60, 2))
                        + " hours"
                    )
                    time.sleep(self.get_interval())
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60, 2))
                        + " hours"
                    )
                    time.sleep(6000)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)
