# -*- coding: utf-8 -*-
"""OpenCTI Malcore connector core module."""

import json
import os
import ssl
import time
import urllib
from datetime import datetime
from urllib import parse

import stix2
import yaml
from pycti import (
    Identity,
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class Malcore:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.api_url = get_config_variable(
            "MALCORE_URL", ["malcore", "api_url"], config
        )
        self.api_key = get_config_variable(
            "MALCORE_API_KEY", ["malcore", "api_key"], config
        )
        self.score = get_config_variable(
            "MALCORE_SCORE", ["malcore", "score"], config, True
        )
        self.limit = get_config_variable(
            "MALCORE_LIMIT", ["malcore", "limit"], config, True
        )
        self.interval = get_config_variable(
            "MALCORE_INTERVAL",
            ["malcore", "interval"],
            config,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Malcore",
            description="Malcore is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet",
        )


    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24 
    
    
    def run_feed_ioc(self, timestamp):
        try: 
            now = datetime.utcfromtimestamp(timestamp)
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
            req.method = "POST"
            body = parse.urlencode(
                {
                    "feed_type": feed_type,
                }
            ).encode()

            response = urllib.request.urlopen(
                req,
                context=ssl.create_default_context(),
                data=body,
            )
            feed = response.read()
            data_json = json.loads(feed)

            identity = stix2.Identity(
                id=Identity.generate_id("Malcore", "organization"),
                name="Malcore",
                identity_class="organization",
            )

            # preparing the bundle to be sent to OpenCTI worker
            file_objects = []

            # Filling the bundle
            for item in data_json['data']['data']:
                
                key = next(iter(item))
                item_data = item[key]
                
                if("file_exif_data" in item_data):
                
                    hashes = item_data["hashes"]
                    upload_time = item_data["upload_time"]
                    file_exif_data = item_data["file_exif_data"]
                    file_extension = file_exif_data['file_information']['file_extension']
                    mime_type = file_exif_data['mime_type']
                    file_size = item_data['file_sizes']['raw_byte_size']
                    hashmd5 = hashes["md5"] 
                    
                    stix_file = stix2.File(
                        name=upload_time+file_extension,
                        hashes={
                            "MD5": hashmd5,    
                            "SHA-1": hashes["sha1"],    
                            "SHA-256": hashes["sha256"],    
                        },
                        size=file_size,
                        mime_type=mime_type,
                    )
                    file_objects.append(stix_file)

            # Creating the bundle from the list
            bundle = stix2.Bundle(
                objects=[identity] + file_objects
            ) 
            bundle_json = bundle.serialize()
            
            # Sending the bundle
            self.helper.send_stix2_bundle(
                bundle_json,
                update=self.update_existing_data,
                work_id=work_id,
            )
            
            message = "IOC successfully run, storing last_run as " + str(
                timestamp
            )
            self.helper.log_info(message)
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
            
        except Exception as e:
            self.helper.log_error(str(e))
            

    def run_feed_threat(self, timestamp):
        try: 
            now = datetime.utcfromtimestamp(timestamp)
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
            req.method = "POST"
            body = parse.urlencode(
                {
                    "feed_type": feed_type,
                }
            ).encode()

            response = urllib.request.urlopen(
                req,
                context=ssl.create_default_context(),
                data=body,
            )
            feed = response.read()
            data_json = json.loads(feed)

            identity = stix2.Identity(
                id=Identity.generate_id("Malcore", "organization"),
                name="Malcore",
                identity_class="organization",
            )

            # preparing the bundle to be sent to OpenCTI worker
            external_reference = stix2.ExternalReference(
                source_name="Malcore database",
                url="https://app.malcore.io/",
                description="Malcore app URL",
            )
            indicators = []
            malware_objects = []
            relationships = []
            labels=['malcore', 'threat']

            # Filling the bundle
            for item in data_json['data']['data']:
                hash = item["hash"] 
                score = item["score"] 
                pattern = "[file:hashes.'SHA-256' = '" + hash + "']"
                
                stix_indicator = stix2.Indicator(
                    id=Indicator.generate_id(hash),
                    name="Indicator: {}".format(hash),
                    description="Hash: {}".format(hash),
                    pattern_type="stix",
                    labels=labels,
                    pattern=pattern,
                    external_references=[external_reference],
                    object_marking_refs=[stix2.TLP_WHITE],
                ) 
                indicators.append(stix_indicator) 
                
                stix_malware = stix2.Malware(
                    id=Malware.generate_id(hash),
                    name="Malware: {}".format(hash),
                    description="Threat Tracked by Malcore",
                    is_family=True,
                    confidence=score,
                    labels=labels,
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
                    labels=labels,
                )
                relationships.append(relationship)

            # Creating the bundle from the list
            bundle = stix2.Bundle(
                objects=[identity] + indicators + malware_objects + relationships
            ) 
            bundle_json = bundle.serialize()
            
            # Sending the bundle
            self.helper.send_stix2_bundle(
                bundle_json,
                update=self.update_existing_data,
                work_id=work_id,
            )
            
            message = "Threat successfully run, storing last_run as " + str(
                timestamp
            )
            self.helper.log_info(message)
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
            
        except Exception as e:
            self.helper.log_error(str(e))
           
           
    def run_feed_hash(self, timestamp):
        try:     
            now = datetime.utcfromtimestamp(timestamp)
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
            req.method = "POST"
            body = parse.urlencode(
                {
                    "feed_type": feed_type,
                }
            ).encode()

            response = urllib.request.urlopen(
                req,
                context=ssl.create_default_context(),
                data=body,
            )
            feed = response.read()
            data_json = json.loads(feed)

            # preparing the bundle to be sent to OpenCTI worker
            external_reference = stix2.ExternalReference(
                source_name="Malcore database",
                url="https://app.malcore.io/",
                description="Malcore app URL",
            )
            bundle_objects = []

            # Filling the bundle
            for item in data_json['data']['data']:
                hash = item["hash"] 
                pattern = "[file:hashes.'SHA-256' = '" + hash + "']"
                
                stix_indicator = stix2.Indicator(
                    id=Indicator.generate_id(hash),
                    pattern_type="stix",
                    labels=['malcore', 'hash'],
                    pattern=pattern,
                    external_references=[external_reference],
                    object_marking_refs=[stix2.TLP_WHITE],
                ) 
                bundle_objects.append(stix_indicator) 

            # Creating the bundle from the list
            bundle = stix2.Bundle(bundle_objects, allow_custom=True)
            bundle_json = bundle.serialize()
            
            # Sending the bundle
            self.helper.send_stix2_bundle(
                bundle_json,
                update=self.update_existing_data,
                work_id=work_id,
            )
            
            message = "Hash successfully run, storing last_run as " + str(
                timestamp
            )
            self.helper.log_info(message)
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
            
        except Exception as e:
            self.helper.log_error(str(e))
            
        
    def run(self):
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")

                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run) > ((int(self.interval) - 1) * 60 * 60 * 24)
                ):
                    # Initiate the run
                    self.helper.log_info("Connector will run!")  
                    
                    # # Run for feed type ioc
                    self.run_feed_ioc(timestamp)
                    
                    # Run for feed type threat
                    self.run_feed_threat(timestamp)
                    
                    # Run for feed type hash
                    self.run_feed_hash(timestamp)
                    
                    # Store the current timestamp as a last run 
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(self.get_interval())
                else:
                    # wait for next run
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)

