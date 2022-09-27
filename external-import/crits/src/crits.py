import os
import sys
import time
import requests
from math import ceil
from datetime import datetime
from dateutil.parser import parse as dtparse

import yaml
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    Identity,
    Report,
    Campaign,
    IntrusionSet,
)
import stix2
import validators


class CRITsConnector:
    def collect_srcs_refs(self, crits_obj):
        # Grab all the source.*.instances.*.references, and import them as a list
        # of External references
        ext_refs = []
        srcs = []
        if "source" in crits_obj.keys():
            for src in crits_obj["source"]:
                sname = src["name"]
                author = stix2.Identity(
                    id=Identity.generate_id(sname, "organization"),
                    name=sname,
                    identity_class="organization",
                )
                srcs.append(author)

                for inst in src["instances"]:
                    ref_params = {
                        "source_name": sname,
                        "description": inst["method"],
                    }
                    if inst["reference"]:
                        if validators.url(inst["reference"]):
                            ref_params["url"] = inst["reference"]
                            ref_params["external_id"] = ""
                        else:
                            ref_params["url"] = ""
                            ref_params["external_id"] = inst["reference"]

                        ext_refs.append(stix2.ExternalReference(**ref_params))

        return srcs, ext_refs

    def campaign_to_stix(self, crits_obj, custom_properties):
        custom_properties["description"] = crits_obj.get("description", "")
        custom_properties["x_opencti_aliases"] = crits_obj.get("aliases", [])

        dynamic_params = {}
        if "created_by_ref" in custom_properties.keys():
            dynamic_params["created_by_ref"] = custom_properties["created_by_ref"]

        if self.crits_import_campaign_as == "Campaign":
            return stix2.Campaign(
                id=Campaign.generate_id(name=crits_obj["name"]),
                name=crits_obj["name"],
                object_marking_refs=[self.default_marking],
                custom_properties=custom_properties,
                **dynamic_params,
            )

        return stix2.IntrusionSet(
            id=IntrusionSet.generate_id(name=crits_obj["name"]),
            name=crits_obj["name"],
            object_marking_refs=[self.default_marking],
            custom_properties=custom_properties,
            **dynamic_params,
        )

    def domain_to_stix(self, crits_obj, custom_properties):
        custom_properties["description"] = crits_obj.get("description", "")

        return stix2.DomainName(
            value=crits_obj["domain"],
            object_marking_refs=[self.default_marking],
            custom_properties=custom_properties,
        )

    def ip_to_stix(self, crits_obj, custom_properties):
        custom_properties["description"] = crits_obj.get("description", "")

        # IP Address observables have 4 subtype possibilities. However,
        # STIX 2.x maps "Address" and "Subnet" to the same data types, for
        # each kind of IP (4 or 6)
        if crits_obj["type"] in ["IPv4 Address", "IPv4 Subnet"]:
            return stix2.IPv4Address(
                value=crits_obj["ip"],
                object_marking_refs=[self.default_marking],
                custom_properties=custom_properties,
            )
        elif crits_obj["type"] in ["IPv6 Address", "IPv6 Subnet"]:
            return stix2.IPv6Address(
                value=crits_obj["ip"],
                object_marking_refs=[self.default_marking],
                custom_properties=custom_properties,
            )

        return None

    def process_objects(self, collection, since):
        http_response = self.make_api_get(
            collection,
            query="?c-{t}__gt={v}&limit={l}".format(
                t=self.crits_timestamp_field, v=since.isoformat(), l=self.chunk_size
            ),
        )

        # Will be used to loop through the pages in the results
        while http_response.ok:
            new_objects = []
            content = http_response.json()

            self.helper.log_info(
                "{c}: total={t} page={n}/{m})".format(
                    c=collection,
                    t=content["meta"]["total_count"],
                    n=int(content["meta"]["offset"] / content["meta"]["total_count"])
                    + 1,
                    m=ceil(content["meta"]["total_count"] / self.chunk_size),
                )
            )

            # Walk through each of the entities and build a stix object
            for crits_obj in content["objects"]:
                # Grab the first Source name from this list, and import it as the author
                srcs, ext_refs = self.collect_srcs_refs(crits_obj)
                new_objects.extend(srcs)

                new_obj = None
                custom_properties = {"x_opencti_score": self.default_score}
                if srcs:
                    custom_properties["created_by_ref"] = srcs[0]["id"]
                    custom_properties["external_references"] = ext_refs

                if collection == "ips":
                    new_obj = self.ip_to_stix(
                        crits_obj=crits_obj, custom_properties=custom_properties
                    )
                elif collection == "domains":
                    new_obj = self.domain_to_stix(
                        crits_obj=crits_obj, custom_properties=custom_properties
                    )
                elif collection == "campaigns":
                    new_obj = self.campaign_to_stix(
                        crits_obj=crits_obj, custom_properties=custom_properties
                    )

                if new_obj:
                    new_objects.append(new_obj)

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "test CRITs upload",
            )

            bundle = stix2.Bundle(objects=new_objects, allow_custom=True).serialize()
            self.helper.send_stix2_bundle(
                bundle, update=self.update_existing_data, work_id=work_id
            )

            # If this is the last page of the collection, then break
            if (
                content["meta"]["offset"] + len(content["objects"])
                >= content["meta"]["total_count"] - 1
            ):
                break

            # Otherwise, load next page
            http_response = self.make_api_get(
                collection,
                query="?c-{t}__gt={v}&limit={l}&offset={o}".format(
                    t=self.crits_timestamp_field,
                    v=since.isoformat(),
                    l=self.chunk_size,
                    o=content["meta"]["offset"] + self.chunk_size,
                ),
            )

        else:
            self.helper.log_warn(
                'Unable to access "{c}" collection, HTTP code: {r}'.format(
                    c=collection,
                    r=http_response.status_code,
                )
            )

    def process_events(self, since):
        http_response = self.make_api_get(
            "events",
            query="?c-{t}__gt={v}&limit={l}".format(
                t=self.crits_timestamp_field, v=since.isoformat(), l=self.chunk_size
            ),
        )

        # Will be used to loop through the pages in the results
        while http_response.ok:
            new_objects = []
            content = http_response.json()

            self.helper.log_info(
                "events: total={t} page={n}/{m})".format(
                    t=content["meta"]["total_count"],
                    n=int(content["meta"]["offset"] / content["meta"]["total_count"])
                    + 1,
                    m=ceil(content["meta"]["total_count"] / self.chunk_size),
                )
            )

            # Walk through each of the entities and build a stix object
            for crits_obj in content["objects"]:
                # Grab the first Source name from this list, and import it as the author

                srcs, ext_refs = self.collect_srcs_refs(crits_obj)
                new_objects.extend(srcs)

                custom_properties = {"x_opencti_report_status": 2}

                ts = dtparse(crits_obj["created"])

                allowed_types = ["IP", "Domain", "Campaign"]
                report_contents_crits = list(
                    filter(
                        lambda x: x["type"] in allowed_types, crits_obj["relationships"]
                    )
                )

                contained_objects = []
                for contained in report_contents_crits:
                    contained_stix = None
                    contained_custom_properties = {
                        "x_opencti_score": self.default_score,
                        "created_by_ref": srcs[0]["id"],
                    }
                    if contained["type"] == "IP":
                        contained_tlo = self.make_api_getobj(
                            collection="ips", objid=contained["value"]
                        )
                        if contained_tlo.ok:
                            contained_stix = self.ip_to_stix(
                                crits_obj=contained_tlo.json(),
                                custom_properties=contained_custom_properties,
                            )
                    elif contained["type"] == "Domain":
                        contained_tlo = self.make_api_getobj(
                            collection="domains", objid=contained["value"]
                        )
                        if contained_tlo.ok:
                            contained_stix = self.domain_to_stix(
                                crits_obj=contained_tlo.json(),
                                custom_properties=contained_custom_properties,
                            )
                    elif contained["type"] == "Campaign":
                        contained_tlo = self.make_api_getobj(
                            collection="campaigns", objid=contained["value"]
                        )
                        if contained_tlo.ok:
                            contained_stix = self.campaign_to_stix(
                                crits_obj=contained_tlo.json(),
                                custom_properties=contained_custom_properties,
                            )

                    if contained_stix:
                        new_objects.append(contained_stix)
                        contained_objects.append(contained_stix["id"])

                # There is also a "Campaign" section, which lists the campaign(s) associated with the
                # event, by name, rather than id. Will also process into contained_objects, but requires
                # special parsing
                for campaign in crits_obj["campaign"]:
                    matching_campaign = self.make_api_get(
                        collection="campaigns",
                        query="?c-name={c}&limit=1".format(c=campaign["name"]),
                    )

                    if matching_campaign.ok:
                        results = matching_campaign.json()
                        if results["meta"]["total_count"] > 0:
                            contained_custom_properties = {
                                "x_opencti_score": self.default_score,
                                "created_by_ref": srcs[0]["id"],
                            }
                            new_obj = self.campaign_to_stix(
                                results["objects"][0],
                                custom_properties=contained_custom_properties,
                            )
                            new_objects.append(new_obj)
                            contained_objects.append(new_obj["id"])

                report_entity = stix2.Report(
                    id=Report.generate_id(crits_obj["title"], ts),
                    name=crits_obj["title"],
                    description=crits_obj.get("description", ""),
                    object_marking_refs=[self.default_marking],
                    published=ts,
                    created=ts,
                    modified=dtparse(crits_obj["modified"]),
                    report_types=[self.crits_event_type],
                    created_by_ref=srcs[0]["id"],
                    external_references=ext_refs,
                    allow_custom=True,
                    custom_properties=custom_properties,
                    object_refs=contained_objects,
                )
                new_objects.append(report_entity)

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "test CRITs upload",
            )

            bundle = stix2.Bundle(objects=new_objects, allow_custom=True).serialize()
            self.helper.send_stix2_bundle(
                bundle, update=self.update_existing_data, work_id=work_id
            )

            # If this is the last page of the collection, then break
            if (
                content["meta"]["offset"] + len(content["objects"])
                >= content["meta"]["total_count"] - 1
            ):
                break

            # Otherwise, load next page
            http_response = self.make_api_get(
                "ips",
                query="?c-{t}__gt={v}&limit={l}&offset={o}".format(
                    t=self.crits_timestamp_field,
                    v=since.isoformat(),
                    l=self.chunk_size,
                    o=content["meta"]["offset"] + self.chunk_size,
                ),
            )

        else:
            self.helper.log_warn(
                'Unable to access "ips" collection, HTTP code: {c}'.format(
                    c=http_response.status_code
                )
            )

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.crits_url = get_config_variable(
            "CRITS_URL",
            ["crits", "url"],
            config,
        )

        # If the admin left the trailing '/' on the CRITS_URL, then strip it from the end of
        # the URL, for consistency later on
        if self.crits_url[-1] == "/":
            self.crits_url = self.crits_url[0:-1]

        self.crits_reference_url = get_config_variable(
            "CRITS_REFERENCE_URL",
            ["crits", "reference_url"],
            config,
            False,
            self.crits_url,
        )
        self.crits_user = get_config_variable(
            "CRITS_USER",
            ["crits", "user"],
            config,
        )
        self.crits_api_key = get_config_variable(
            "CRITS_API_KEY",
            ["crits", "api_key"],
            config,
        )
        self.crits_event_type = get_config_variable(
            "CRITS_EVENT_TYPE", ["crits", "event_type"], config, False, "crits-event"
        )
        self.crits_interval = get_config_variable(
            "CRITS_INTERVAL", ["crits", "interval"], config, True
        )
        self.crits_import_campaign_as = get_config_variable(
            "CRITS_IMPORT_CAMPAIGN_AS",
            ["crits", "import_campaign_as"],
            config,
            isNumber=False,
            default="IntrusionSet",
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            isNumber=False,
            default=True,
        )
        self.crits_timestamp_field = "modified"
        self.chunk_size = 100
        self.default_marking = stix2.TLP_GREEN
        self.default_score = 75

        # Test connection to <crits_url>/api/v1/events/?limit=1, which should give a JSON result
        # if the authentication is working, whether or not there's any Events in the database.
        # 401 Unauthorized will be the result code, if the authentication doesn't work
        http_response = self.make_api_get(collection="events", query="?limit=1")
        http_response.raise_for_status()
        self.helper.log_info(
            "Success authenticating to CRITs {url}".format(url=self.crits_url)
        )

    def make_api_get(self, collection, query=""):
        if query and query[0] != "?":
            query = "?{q}".format(q=query)

        http_response = requests.get(
            "{base}/api/v1/{collection}/{query}".format(
                base=self.crits_url, collection=collection, query=query
            ),
            params={"username": self.crits_user, "api_key": self.crits_api_key},
        )
        return http_response

    def make_api_getobj(self, collection, objid):
        http_response = requests.get(
            "{base}/api/v1/{collection}/{objid}/".format(
                base=self.crits_url, collection=collection, objid=objid
            ),
            params={"username": self.crits_user, "api_key": self.crits_api_key},
        )
        return http_response

    def run(self):
        while True:
            #
            # Some key considerations to keep in mind:
            # - CRITs allows storage of various entities without requiring they be part of a "Event"
            # - Event is a TLO that we'll consider analogous to "Analysis report" in OpenCTI
            # - CRITs tracks relationships between all entities the same, using a specific taxonomy that's built in for reltype,
            #   but using exclusively the BSON ObjectId associated to the relationships
            # - CRITs doesn't strictly adhere to STIX, and where it tries to, it's STIX 1.x
            # - CRITs doesn't offer API listing of "Sources", so these must be organically collected during the processing
            #   of entitites
            # - CRITs "Campaign" links to entities is handled as a unique relationship that uses the text of the campaign
            #   name, rather than its entity id, in a custom purpose-specific field. Interestingly enough, the generic
            #   relationships can also link to a campaign, so there's two relational mechanisms to keep in mind for this
            # - CRITs "Campaign" covers both "Intrusion Set" and "Campaign" in OpenCTI taxonomy
            # - CRITs doesn't associate TLO or Campaign relationships with Events or other sourcing info
            # - CRITs doesn't require that "external references" necessitate any corresponding Event objects
            # - CRITs allows other TLOs to share external references with Events, but leaves it to analysts to relate them. This
            #   should probably be used to help clean up dirty related data on import (maybe as a togglable)
            # - CRITs has TLOs that map to some "Observation" types, as well as some Entity types, in OpenCTI.
            #   Furthermore, there are sub-types of Indicator that map to even more Observations for which there's no TLO.
            #   There likely will need to be some mechanism similar to how MISP ingest works to optionally create
            #   "indicators" or "observables" or "both", for any of the sub-types of "Indicator" TLOs
            # - ... TO BE CONTINUED
            #
            # Ingest plan (likely) will consist of the following phases:
            #
            # A) Walk through each of CRITs "Top Level Objects" (TLOs) that map 1-to-1 to an OpenCTI Object type, except for
            #    Events
            #    1) Format into a STIX2 bundle, and have it ingested
            #    2) CRITs API uses pagination, so perform this work 100 at a time to reduce memory usage
            #    3) Import these bundles into OpenCTI
            #
            # B) Walk through all CRITs Events, and import them with "contains" relationships to the other TLOs that they relate to
            #    ... Do 1-3 from above
            #
            # C) Go back through and mine relationships out of the dataset, and populate those over into OpenCTI
            #    1) CRITs relationships aren't tied to source reporting. Do I store the relation in all reports containing
            #       both elements? Neither?
            #    2) Upload the relationships - walk through containing reports, if needed
            #
            tmp_earliest = datetime(2010, 1, 1)

            # First, collect up reports, which will initially populate using the Report-centric object model
            self.process_events(since=tmp_earliest)

            # Second, collect entities and observables and other objects that can be created without relating to Reports/Events
            for collection in ["ips", "domains", "campaigns"]:
                self.process_objects(collection=collection, since=tmp_earliest)

            time.sleep(60 * self.crits_interval)


if __name__ == "__main__":
    try:
        connector = CRITsConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
