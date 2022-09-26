import os
import sys
import time
import requests

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class CRITsConnector:
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
            time.sleep(60 * self.crits_interval)


if __name__ == "__main__":
    try:
        connector = CRITsConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
