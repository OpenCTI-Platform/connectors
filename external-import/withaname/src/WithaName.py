import datetime
import json
import os
import sys
import time

import requests
import stix2
import yaml
from pycti import (
    Tool,
    ThreatActor,
    AttackPattern,
    Campaign,
    Location,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class WithaName:
    """WithaName connector"""

    def __init__(self):
        """Initializer"""
        # ==============================================================
        # This part is common to all connectors, it loads the config file, and the parameters to local variables
        # ==============================================================
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config_file_path = config_file_path.replace("\\", "/")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Extra config
        # URL: 'https://witha.name/data/last.json'
        self.withaname_url = get_config_variable(
            "WITHANAME_URL",
            ["withaname", "url"],
            config,
            default="https://witha.name/data/last.json",
        )
        #   save_domain: 'true/false'
        self.withaname_save_domain = get_config_variable(
            "WITHANAME_SAVE_DOMAIN",
            ["withaname", "save_domain"],
            config,
            default=False,
        )
        #   save_ip: 'true/false''
        self.withaname_save_ip = get_config_variable(
            "WITHANAME_SAVE_IP",
            ["withaname", "save_ip"],
            config,
            default=False,
        )
        #   save_url: 'true/false''
        self.withaname_save_url = get_config_variable(
            "WITHANAME_SAVE_URL",
            ["withaname", "save_url"],
            config,
            default=False,
        )
        #   link_tool: 'DDoSia'
        self.withaname_link_tool = get_config_variable(
            "WITHANAME_LINK_TOOL",
            ["withaname", "link_tool"],
            config,
            default="",
        )
        # linl_ta: 'Noname057'
        self.withaname_link_ta = get_config_variable(
            "WITHANAME_LINK_TA",
            ["withaname", "link_ta"],
            config,
            default="",
        )
        # link_ap: 'T1498 Network Denial of Service'
        self.withaname_link_ap = get_config_variable(
            "WITHANAME_LINK_AP",
            ["withaname", "link_ap"],
            config,
            default="T1498 Network Denial of Service",
        )
        # link_country: 'true/false''
        self.withaname_link_country = get_config_variable(
            "WITHANAME_LINK_COUNTRY",
            ["withaname", "link_country"],
            config,
            default=False,
        )
        # links_duration: 24h
        self.withaname_links_duration = get_config_variable(
            "WITHANAME_LINKS_DURATION",
            ["withaname", "links_duration"],
            config,
            isNumber=True,
            default=24,
        )
        #   interval: 2
        self.withaname_interval = get_config_variable(
            "WITHANAME_INTERVAL",
            ["withaname", "interval"],
            config,
            isNumber=True,
            default=2,
        )
        #   interval: 2
        self.withaname_shifthour = get_config_variable(
            "WITHANAME_SHIFTHOUR",
            ["withaname", "shifthour"],
            config,
            isNumber=True,
            default=6,
        )
        #   Marking: TLP:GREEN
        self.withaname_marking = get_config_variable(
            "WITHANAME_MARKING",
            ["withaname", "marking_definition"],
            config,
            default="TLP:GREEN",
        )
        # WITHANAME_CREATE_DAILY_CAMPAIGNS: true/false
        self.withaname_create_daily_campaigns = get_config_variable(
            "WITHANAME_CREATE_DAILY_CAMPAIGNS",
            ["withaname", "create_daily_campaigns"],
            config,
            default=True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            default=False,
        )

        self.helper.connector_logger.debug("WithaName connector initialized.")
        self.helper.connector_logger.debug(f"WithaName url:            {self.withaname_url}.")
        self.helper.connector_logger.debug(f"WithaName save_domain:    {self.withaname_save_domain}.")
        self.helper.connector_logger.debug(f"WithaName save_ip:        {self.withaname_save_ip}.")
        self.helper.connector_logger.debug(f"WithaName save_url:       {self.withaname_save_url}.")
        self.helper.connector_logger.debug(f"WithaName link_tool:      {self.withaname_link_tool}.")
        self.helper.connector_logger.debug(f"WithaName link_ta:        {self.withaname_link_ta}.")
        self.helper.connector_logger.debug(f"WithaName link_ap:        {self.withaname_link_ap}.")
        self.helper.connector_logger.debug(f"WithaName link_country:   {self.withaname_link_country}.")
        self.helper.connector_logger.debug(f"WithaName links_duration: {self.withaname_links_duration}.")
        self.helper.connector_logger.debug(f"WithaName interval:       {self.withaname_interval} hours.")
        self.helper.connector_logger.debug(f"WithaName shifthour:      {self.withaname_shifthour} hours.")
        self.helper.connector_logger.debug(f"WithaName marking:        {self.withaname_marking}.")
        self.helper.connector_logger.debug(f"WithaName update_existing:{self.update_existing_data}.")
        
        
    def set_marking(self):
        if self.withaname_marking == "TLP:WHITE" or self.withaname_marking == "TLP:CLEAR":
            marking = stix2.TLP_WHITE
        elif self.withaname_marking == "TLP:GREEN":
            marking = stix2.TLP_GREEN
        elif self.withaname_marking == "TLP:AMBER":
            marking = stix2.TLP_AMBER
        elif self.withaname_marking == "TLP:AMBER+STRICT":
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )
        elif self.withaname_marking == "TLP:RED":
            marking = stix2.TLP_RED
        else:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="TLP",
                definition={"TLP": "AMBER+STRICT"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )

        self.withaname_marking = marking

    def withaname_api_get_list(self):
        try:
            headers = {
                "User-Agent": "OpenCTI-WithaName-Connector/1.1",
                "ContentType": "application/json"
                }
            # Get the full list of IOC from WithaName
            self.helper.connector_logger.debug(f"Retreiving raw data at : {self.withaname_url}.")
            Raw_Data = requests.get(
                    self.withaname_url, headers=headers, verify=True, timeout=(80000, 80000)
                )
            self.helper.connector_logger.debug(f"We get a response from WithaName API: {Raw_Data.status_code}.")
            if Raw_Data.status_code != 200:
                self.helper.connector_logger.error(
                    f"Error while getting data from WithaName API: {Raw_Data.status_code}, let's get out of here without data :("
                )
                return {}
            _json = Raw_Data.json()
            # Check if the local copy is the same as remote
            Last_file = "last_witha_name_run.json"
            if os.path.exists(Last_file):
                self.helper.connector_logger.debug(f"We have a local last conf: {Last_file}.")
                last_data = json.load(open(Last_file, "r"))
                if last_data == _json:
                    self.helper.connector_logger.info("No new data from WithaName since last run, skipping processing.")
                    return {}
                else:
                    self.helper.connector_logger.debug("It's a new config from WithaName.")
            else:
                self.helper.connector_logger.info("It's a dry run no WithaName last.")
            # Save the last data locally
            self.helper.connector_logger.info(f"Saving the last WithaName data locally to {Last_file}.")
            json.dump(_json, open(Last_file, "w"), indent=4)
            # Process the data
            targets_json = _json['targets']
            self.helper.connector_logger.info(f"We retreive: {len(targets_json)} target infos.")
            
            withaname_result={}
            for one_target in targets_json:
                # our keys is domain:IP (even if DDoSia Target IP not domain...)
                
                # Intialize to None
                target_domain = None
                target_ip = None
                target_url = None
                # Try to affect
                try:
                    target_domain = one_target["host"]
                except Exception as inst:
                    self.helper.connector_logger.error(f"Error during host retreiving {inst}")
                    target_domain = "Err"
                try:
                    target_ip = one_target["ip"]
                except Exception as inst:
                    self.helper.connector_logger.error(f"Error during ip retreiving {inst}")
                    target_ip = "Err"
                try:
                    target_url = f"{one_target['type']}://{one_target['host']}{one_target['path']}"
                except Exception as inst:
                    self.helper.connector_logger.error(f"Error during url retreiving {inst}")
                    target_url = "Err"
                
                Dict_key=f"{target_domain}:{target_ip}".lower()
                if Dict_key in withaname_result.keys():
                    # Update (add url and raw data)
                    if not target_url in withaname_result[Dict_key]["urls"]: withaname_result[Dict_key]["urls"].append(target_url)
                    if not one_target in withaname_result[Dict_key]["raw"]:withaname_result[Dict_key]["raw"].append(one_target)
                else:
                    # Create
                    withaname_result[Dict_key]={
                        "domain":target_domain,
                        "ip":target_ip,
                        "urls":[target_url],
                        "raw": [one_target]
                    }

            return withaname_result
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while getting intelligence from WithaName: {e}"
            )
        return {}

    def create_stix_object(self, target, identity_id, start_time=None, stop_time=None):
        # Reminder: target[domain:ip] =
        #{
        #     "domain":target_domain,
        #     "ip":target_ip,
        #     "urls":[target_url,target_url2,target_url3...],
        #     "raw": [raw_target,raw_target2,raw_target3...]
        # }
        # identity_id = OCTI Identity ID for WithaName
        stix_objects = []
        # self.helper.connector_logger.debug(target)
        # We generate STIX objects from each domain entry
        description  = "Imported from WithaName API at "+datetime.datetime.now().strftime("%Y-%m-%d")+". \n"
        description += "All informations: \n"
        description += f" - Domain: {target["domain"]} \n"
        description += f" - IP: {target["ip"]} \n"
        description += " - URLs: \n"
        for one_url in target["urls"]:
            description += f"   + {one_url} \n"
        description += "Full Raw Data \n"
        description += "-------------------------------- \n"
        description += json.dumps(target["raw"],indent=4)+" \n"
        description += "-------------------------------- \n"
        
        # STIX: Create Observables
        self.helper.connector_logger.debug("New target to process")
        try:
            Observables = []
            master_observable_id = None
            if self.withaname_save_domain:
                name = target["domain"]
                self.helper.connector_logger.debug(f" > Target has a domain: {name}.")
                observable_d = stix2.DomainName(
                    value=name,
                    object_marking_refs=[self.withaname_marking],
                    custom_properties={
                        "x_opencti_score": 80,
                        "x_opencti_description": description,
                        "created_by_ref": identity_id,
                           "x_opencti_labels": ["DDoS", "witha.name"],
                    },
                )
                Observables.append(observable_d)
                if master_observable_id is None: master_observable_id=observable_d["id"]
                del observable_d
            if self.withaname_save_ip:
                name = target["ip"]
                self.helper.connector_logger.debug(f" > Target has an ip: {name}.")
                observable_i = stix2.IPv4Address(
                    value=name,
                    object_marking_refs=[self.withaname_marking],
                    custom_properties={
                        "x_opencti_score": 80,
                        "x_opencti_description": description,
                        "created_by_ref": identity_id,
                           "x_opencti_labels": ["DDoS", "witha.name"],
                    },
                )
                Observables.append(observable_i)
                if master_observable_id is None: master_observable_id=observable_i["id"]
                del observable_i
            if self.withaname_save_url:
                for one_url in target["urls"]:
                    name = one_url
                    self.helper.connector_logger.debug(f" > Target has url: {one_url}.")
                    observable_u = stix2.URL(
                        value=name,
                        object_marking_refs=[self.withaname_marking],
                        custom_properties={
                            "x_opencti_score": 80,
                            "x_opencti_description": description,
                            "created_by_ref": identity_id,
                            "x_opencti_labels": ["DDoS", "witha.name"],
                        },
                    )
                    Observables.append(observable_u)
                    if master_observable_id is None: master_observable_id=observable_u["id"]
                    del observable_u
            # We add all Observables created
            for observable in Observables:
                stix_objects.append(observable)
            # Linking all to master id (mostly Domain-name)
            if not master_observable_id is None:
                for observable in Observables:
                    if observable["id"] == master_observable_id: continue
                    self.helper.connector_logger.debug(f" [+] StixCoreRelationship creation between MasterObservable and Observable ({master_observable_id} > {observable["value"]}).")
                    relation_OO = stix2.Relationship(
                        id=StixCoreRelationship.generate_id("related-to", master_observable_id, observable["id"], start_time=start_time, stop_time=stop_time),
                        source_ref=master_observable_id,
                        target_ref=observable["id"],
                        relationship_type="related-to",
                        created_by_ref=identity_id,
                        start_time=start_time,
                        stop_time=stop_time,
                        object_marking_refs=[self.withaname_marking],
                        description=f"Link between observable for witha.name at {datetime.datetime.now().strftime("%Y-%m-%d")}. (Link ObsObs)"
                    )
                    stix_objects.append(relation_OO)
                    del relation_OO
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from threat: {observable["value"]}, error: {e}"
            )
            return None
        
        # STIX: Linking Tool (StixCoreRelationship)
        # Linking Elements with Tool/Threat-Actor/Attack-Pattern/Country/Campaign if requested        
        for observable in Observables:
            self.helper.connector_logger.debug(f"  -  Working on observable created: {observable['value']}.")
            try:
                if self.withaname_link_tool_id is None:
                    self.helper.connector_logger.debug("    [-] No Link with Tool requested.")
                else:
                    # STIX: StixCoreRelationship Observable --> Tool
                    self.helper.connector_logger.debug(f"    [+] StixCoreRelationship creation between Tool and Observable ({self.withaname_link_tool} > {observable["value"]}).")
                    relation_OT = stix2.Relationship(
                        id=StixCoreRelationship.generate_id("related-to", self.withaname_link_tool_id, observable["id"], start_time=start_time, stop_time=stop_time),
                        source_ref=self.withaname_link_tool_id,
                        target_ref=observable["id"],
                        relationship_type="related-to",
                        created_by_ref=identity_id,
                        start_time=start_time,
                        stop_time=stop_time,
                        object_marking_refs=[self.withaname_marking],
                        description=f"Was targeted by {self.withaname_link_tool} between {start_time} and {stop_time}. (Link ObsTool)"
                    )
                    stix_objects.append(relation_OT)
                    del relation_OT
            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error while creating STIX object from Tool: {self.withaname_link_tool}, error: {e}"
                )
            # STIX: Linking Threat-Actor (StixCoreRelationship)
            try:
                if self.withaname_link_ta_id is None:
                    self.helper.connector_logger.debug("    [-] No Link with Threat Actor requested.")
                else:
                    # STIX: StixCoreRelationship Observable --> Threat-Actor
                    self.helper.connector_logger.debug(f"    [+] StixCoreRelationship creation between Threat-Actor and Observable ({self.withaname_link_ta} > {observable["value"]}).")
                    relation_OA = stix2.Relationship(
                        id=StixCoreRelationship.generate_id("related-to", self.withaname_link_ta_id, observable["id"], start_time=start_time, stop_time=stop_time),
                        source_ref=self.withaname_link_ta_id,
                        target_ref=observable["id"],
                        relationship_type="related-to",
                        created_by_ref=identity_id,
                        start_time=start_time,
                        stop_time=stop_time,
                        object_marking_refs=[self.withaname_marking],
                        description=f"Was targeted by {self.withaname_link_ta} between {start_time} and {stop_time}. (Link ObsActor)"
                    )
                    stix_objects.append(relation_OA)
                    del relation_OA
            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error while creating STIX object from Threat-Actor: {self.withaname_link_ta}, error: {e}"
                )
            # STIX: Linking Attack-Pattern (StixCoreRelationship)
            try:
                if self.withaname_link_ap_id is None:
                    self.helper.connector_logger.debug("    [-] No Link with Tool requested.")
                else:
                    # STIX: StixCoreRelationship Observable --> Attack-Pattern
                    self.helper.connector_logger.debug(f"    [+] StixCoreRelationship creation between Attack-Pattern and Observable ({self.withaname_link_ap} > {observable["value"]}).")
                    relation_OAP = stix2.Relationship(
                        id=StixCoreRelationship.generate_id("related-to", self.withaname_link_ap_id, observable["id"], start_time=start_time, stop_time=stop_time),
                        source_ref=self.withaname_link_ap_id,
                        target_ref=observable["id"],
                        relationship_type="related-to",
                        created_by_ref=identity_id,
                        start_time=start_time,
                        stop_time=stop_time,
                        object_marking_refs=[self.withaname_marking],
                        description=f"Was targeted by {self.withaname_link_ap} between {start_time} and {stop_time}. (Link ObsAttackPattern)"
                    )
                    stix_objects.append(relation_OAP)
                    del relation_OAP
            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error while creating STIX object from Attack-Pattern: {self.withaname_link_ta}, error: {e}"
                )
            # STIX: Linking Country (for domain IOC based on TLD) (StixCoreRelationship)
            country_targeted = None
            try:
                if self.withaname_link_country and observable["type"]=="domain-name":
                    tld = observable["value"].split('.')[-1].upper()
                    if len(tld) != 2:
                        self.helper.connector_logger.debug(f"    [-] Target TLD {tld} is not a country code, skipping...")
                    else:
                        self.helper.connector_logger.debug(f"     > Target TLD {tld} is a country code, linking country.")
                        country_targeted = stix2.Location(
                            id=Location.generate_id(f"[location:value = '{tld}']","Country"),
                            country=tld,
                            custom_properties={"x_opencti_score": 50, },
                        )
                        self.helper.connector_logger.debug(f"     > Target TLD {tld} is {country_targeted['country']}.")
                        # country_targeted.x_opencti_score = 50
                        stix_objects.append(country_targeted)
                        # STIX: StixCoreRelationship Observable --> Targeted Country
                        self.helper.connector_logger.debug(f"    [+] StixCoreRelationship creation between Country and Observable ({country_targeted['country']} > {observable["value"]}).")
                        relation_TC = stix2.Relationship(
                            id=StixCoreRelationship.generate_id("related-to", country_targeted["id"], observable["id"], start_time=start_time, stop_time=stop_time),
                            source_ref=country_targeted["id"],
                            target_ref=observable["id"],
                            relationship_type="related-to",
                            created_by_ref=identity_id,
                            start_time=start_time,
                            stop_time=stop_time,
                            object_marking_refs=[self.withaname_marking],
                            custom_properties={"x_opencti_score": 50,"x_opencti_labels": ["witha.name"],},
                            description=f"Was targeted by {self.withaname_link_ta} between {start_time} and {stop_time}. (Link ObsCountry)"
                        )
                        # relation_TC.x_opencti_score = 50
                        stix_objects.append(relation_TC)
                        
                        # STIX: StixCoreRelationship Country --> campaign
                        if not self.withaname_link_campaign_id is None:
                            self.helper.connector_logger.debug(f"    [+] StixCoreRelationship creation between Campaign 'targets' Country ({self.withaname_link_campaign_id} > {country_targeted['country']} ).")
                            relation_CC = stix2.Relationship(
                                id=StixCoreRelationship.generate_id("targets", self.withaname_link_campaign_id, country_targeted["id"], start_time=start_time, stop_time=stop_time),
                                source_ref=self.withaname_link_campaign_id,
                                target_ref=country_targeted["id"],
                                relationship_type="targets",
                                created_by_ref=identity_id,
                                start_time=start_time,
                                stop_time=stop_time,
                                object_marking_refs=[self.withaname_marking],
                                custom_properties={"x_opencti_score": 50,"x_opencti_labels": ["witha.name"],},
                                description=f"Was targeted by {self.withaname_link_ta} between {start_time} and {stop_time}.   (Link CountryCampaign)"
                            )
                            # relation_CC.x_opencti_score = 50
                            stix_objects.append(relation_CC)
                            del relation_CC
                        del relation_TC
                        country_targeted = None
            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error while creating STIX object from Country link: {self.withaname_link_ta}, error: {e}"
                )
            # STIX: Linking Campaign (StixCoreRelationship)
            try:
                if self.withaname_link_campaign_id is None:
                    self.helper.connector_logger.debug("    [-] No campaingn requested.")
                else:
                    # STIX: Relationship Observable --> campaign
                    self.helper.connector_logger.debug(f"    [+] StixCoreRelationship creation between Campaign and Observable ({self.withaname_link_campaign_id} > {observable["value"]}).")
                    relation_OC = stix2.Relationship(
                        id=StixCoreRelationship.generate_id("related-to", self.withaname_link_campaign_id, observable["id"], start_time=start_time, stop_time=stop_time),
                        source_ref=self.withaname_link_campaign_id ,
                        target_ref=observable["id"],
                        relationship_type="related-to",
                        created_by_ref=identity_id,
                        start_time=start_time,
                        stop_time=stop_time,
                        object_marking_refs=[self.withaname_marking],
                        description=f"Was targeted between {start_time} and {stop_time}. (Link ObsCampaign)"
                    )
                    stix_objects.append(relation_OC)
                    del relation_OC
            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error while creating STIX object from Country link: {self.withaname_link_ta}, error: {e}"
                )    
        # ---------------------------------------------------------------
        return stix_objects

    def create_stix_bundle(self, targeted):
        # create start_date (day 06:00) (can by changed with self.withaname_shifthour)
        start_date = datetime.datetime.now().replace(hour=self.withaname_shifthour, minute=0, second=0, microsecond=0)
        # creat end_date tomoraw 06:00 (usual duration is 24h)
        end_date = start_date + datetime.timedelta(hours=self.withaname_links_duration)

        if start_date.hour<self.withaname_shifthour:
            start_date = start_date + datetime.timedelta(hours=-24)
            end_date = end_date + datetime.timedelta(hours=-24)

        # Create the Identity for WithaName Import
        identity_id = "identity--8d81c32c-e8d3-55b9-b3ff-558bd127e4fb"
        identity = stix2.Identity(
            id=identity_id,
            spec_version="2.1",
            name="Witha.name",
            confidence=60,
            created="2024-11-02T00:00:00.000Z",
            modified="2025-12-08T10:03:08.243Z",
            identity_class="individual",
            type="identity",
            object_marking_refs=stix2.TLP_WHITE,
        )
        stix_objects = [identity, self.withaname_marking]
        # Creating the tool (DDoSia) if needed
        self.withaname_link_tool_id = None
        try:
            if len(self.withaname_link_tool) > 0:
                self.helper.connector_logger.debug(f"Tool dreation: {self.withaname_link_tool}.")
                tool = stix2.Tool(
                    id=Tool.generate_id(f"[tool:value = '{self.withaname_link_tool}']"),
                    name=self.withaname_link_tool,
                    created_by_ref=identity_id,
                    object_marking_refs=[self.withaname_marking],
                )
                stix_objects.append(tool)
                self.withaname_link_tool_id = tool["id"]
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from Tool: {self.withaname_link_tool}, error: {e}"
            )

        # Creating the Threat-Actor (Noname057) if needed
        self.withaname_link_ta_id = None
        try:
            if len(self.withaname_link_ta) > 0:
                self.helper.connector_logger.debug(f"Threat-Actor Creation: {self.withaname_link_ta}.")
                threat_actor = stix2.ThreatActor(
                    id=ThreatActor.generate_id(f"[threat-actor:value = '{self.withaname_link_ta}']",opencti_type="Threat-Actor-Group"),
                    name=self.withaname_link_ta,
                    created_by_ref=identity_id,
                    object_marking_refs=[self.withaname_marking],
                )
                stix_objects.append(threat_actor)
                self.withaname_link_ta_id = threat_actor["id"]
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from TheatActor: {self.withaname_link_tool}, error: {e}"
            )
        
        # Creating the Attack Patter (T1498 Network Denial of Service) if needed
        self.withaname_link_ap_id = None
        try:
            if len(self.withaname_link_ap) > 0:
                self.helper.connector_logger.debug(f"Attack-Patter Creation: {self.withaname_link_ap}.")
                ddos_attack = stix2.AttackPattern(
                    id=AttackPattern.generate_id(f"[attack-pattern:value = {self.withaname_link_ap}]"),
                    name=f"{self.withaname_link_ap}",
                    description="Attaque visant à saturer les ressources réseau.",
                )
                stix_objects.append(ddos_attack)
                self.withaname_link_ap_id = ddos_attack["id"]
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from Attack-Patter: {self.withaname_link_ap}, error: {e}"
            )

        # Creating the Campaign if needed
        self.withaname_link_campaign_id = None
        try:
            if self.withaname_create_daily_campaigns:
                # Counting IP dans Domaines/urls targeted ont his campaign
                IP_List = []
                Domain_List = []
                URLs_List=[]
                for one_target in targeted.keys():
                    # Reminder: target[domain:ip] =
                    #{
                    #     "domain":target_domain,
                    #     "ip":target_ip,
                    #     "urls":[target_url,target_url2,target_url3...],
                    #     "raw": [raw_target,raw_target2,raw_target3...]
                    # }
                    target = targeted[one_target]
                    if not(target["ip"] in IP_List): IP_List.append(target["ip"])
                    if not(target["domain"] in Domain_List):Domain_List.append(target["domain"])
                    for one_url in target["urls"]:
                        if not(one_url in URLs_List):URLs_List.append(one_url)    
                
                campaign_Name = f"{self.withaname_link_tool} {datetime.datetime.now().strftime('%Y-%m-%d  %H:%M')}"
                campaign_Description = f"Campaign related to DDoS attack imported from WithaName on {datetime.datetime.now().strftime('%Y-%m-%d')}. \n Targeted Domains/IPs/URLs: {len(Domain_List)}/{len(IP_List)}/{len(URLs_List)}."
                self.helper.connector_logger.debug(f"Creating daily {self.withaname_link_tool} campaign for today ({campaign_Name}).")
                campaign = stix2.Campaign(
                    id=Campaign.generate_id(f"[campaign:value = {campaign_Name}]"),
                    name=campaign_Name,
                    description=campaign_Description,
                    object_marking_refs=[self.withaname_marking],
                    first_seen = start_date,
                    last_seen = end_date,
                    custom_properties={
                        "x_opencti_score": 80,
                        "created_by_ref": identity_id,
                        "x_opencti_labels": ["DDoS", "witha.name"],
                    },
                )
                del campaign_Description,campaign_Name, IP_List,Domain_List,URLs_List
                stix_objects.append(campaign)
                self.withaname_link_campaign_id = campaign["id"]
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from Campaign: {self.withaname_link_tool}, error: {e}"
            )
        
        # Relation Between Campaign 'attributed-to' Threat Actor
        try:
            if not ( self.withaname_link_campaign_id is None or self.withaname_link_ta_id is  None):
                self.helper.connector_logger.debug(f"StixCoreRelationship 'attributed-to' creation between Campaign and ThreatActor ({self.withaname_link_campaign_id} > {self.withaname_link_ta_id} ).")
                relation_CTA = stix2.Relationship(
                    id=StixCoreRelationship.generate_id("attributed-to", self.withaname_link_campaign_id, self.withaname_link_ta_id, start_time=start_date, stop_time=end_date),
                    source_ref=self.withaname_link_campaign_id,
                    target_ref=self.withaname_link_ta_id,
                    relationship_type="attributed-to",
                    created_by_ref=identity_id,
                    start_time=start_date,
                    stop_time=end_date,
                    object_marking_refs=[self.withaname_marking],
                    description=f"Daily campaign {self.withaname_link_ta}.  (Link CampaignThreatActor)"
                )
                stix_objects.append(relation_CTA)
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX Relationship object between Campaign and ThreatActor, error: {e}"
            )
        
        # Relation Between Campaign 'uses' Tool
        try:
            if not ( self.withaname_link_campaign_id is None or self.withaname_link_tool_id is  None):
                self.helper.connector_logger.debug(f"StixCoreRelationship 'uses' creation between Campaign and Tool ({self.withaname_link_campaign_id} > {self.withaname_link_ta_id} ).")
                relation_CTA = stix2.Relationship(
                    id=StixCoreRelationship.generate_id("uses", self.withaname_link_campaign_id, self.withaname_link_tool_id, start_time=start_date, stop_time=end_date),
                    source_ref=self.withaname_link_campaign_id,
                    target_ref=self.withaname_link_tool_id,
                    relationship_type="uses",
                    created_by_ref=identity_id,
                    start_time=start_date,
                    stop_time=end_date,
                    object_marking_refs=[self.withaname_marking],
                    description=f"Campaign use {self.withaname_link_tool}.  (Link CampaignTool)"
                )
                stix_objects.append(relation_CTA)
        except Exception as e:
            self.helper.connector_logger.error(
               f"Error while creating STIX Relationship object between Campaign and Tool, error: {e}"
            )

        # Finally Creating the Observables from targeted list
        for one_key in  targeted.keys():
            stix_object = self.create_stix_object(targeted[one_key], identity_id)
            if stix_object: stix_objects.extend(stix_object)
                
        #----------------------------------------------------

        bundle = stix2.Bundle(
            objects=stix_objects,
            allow_custom=True,
        )
        return bundle

    def opencti_bundle(self, work_id):
        targeted = self.withaname_api_get_list()
        if targeted is None:
            self.helper.connector_logger.info("No data retrieved from WithaName API (None), skipping bundle creation.")
        elif len(targeted.keys()) == 0:
            self.helper.connector_logger.info("No data retrieved from WithaName API (empty), skipping bundle creation.")
        else:
            try:
                stix_bundle = self.create_stix_bundle(targeted)
                # Convert the bundle to a dictionary
                stix_bundle_dict = json.loads(stix_bundle.serialize())

                stix_bundle_dict = json.dumps(stix_bundle_dict, indent=4)
                self.helper.send_stix2_bundle(
                    stix_bundle_dict, update=self.update_existing_data, work_id=work_id
                )
            except Exception as e:
                self.helper.connector_logger.error(str(e))

    def send_bundle(self, work_id, serialized_bundle: str):
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.connector_logger.error(f"Error while sending bundle: {e}")

    def process_data(self):
        try:
            self.helper.connector_logger.info("Synchronizing with WithaName APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            friendly_name = "WithaName run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            if current_state is None:
                self.helper.set_state(
                    {"last_run": str(now.strftime("%Y-%m-%d %H:%M:%S"))}
                )
            current_state = self.helper.get_state()
            self.helper.connector_logger.info(
                "Get IOC since " + current_state["last_run"]
            )
            self.opencti_bundle(work_id)
            self.helper.set_state({"last_run": now.astimezone().isoformat()})
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)
            time.sleep(self.withaname_interval)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(str(e))

    def run(self):
        self.helper.connector_logger.info("Fetching WithaName datasets...")
        self.set_marking()
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.withaname_interval * 60 * 60)


if __name__ == "__main__":
    try:
        WithaNameConnector = WithaName()
        WithaNameConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)