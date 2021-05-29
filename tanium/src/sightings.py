#################
# SIGHTINGS     #
#################

import threading
import time

from dateutil.parser import parse


class Sightings(threading.Thread):
    def __init__(self, helper, tanium_api_handler):
        threading.Thread.__init__(self)
        self.helper = helper
        self.tanium_api_handler = tanium_api_handler

        # Identity
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name=self.helper.get_name(),
            description=self.helper.get_name(),
        )

    def run(self):
        self.helper.log_info("[SIGHTINGS] Starting alerts gatherer")
        while True:
            alerts = self.tanium_api_handler._query(
                "get", "/plugin/products/detect3/api/v1/alerts", {"sort": "-createdAt"}
            )
            state = self.helper.get_state()
            if state and "lastAlertTimestamp" in state:
                last_timestamp = state["lastAlertTimestamp"]
            else:
                last_timestamp = 0
            alerts = reversed(alerts)
            for alert in alerts:
                alert_timestamp = parse(alert["createdAt"]).timestamp()
                if int(alert_timestamp) > int(last_timestamp):
                    # Mark as processed
                    if state is not None:
                        state["lastAlertTimestamp"] = int(
                            round(parse(alert["createdAt"]).timestamp())
                        )
                        self.helper.set_state(state)
                    else:
                        self.helper.set_state(
                            {
                                "lastAlertTimestamp": int(
                                    round(parse(alert["createdAt"]).timestamp())
                                )
                            }
                        )
                    # Check if the intel is in OpenCTI
                    external_reference = self.helper.api.external_reference.read(
                        filters=[
                            {"key": "source_name", "values": ["Tanium"]},
                            {
                                "key": "external_id",
                                "values": [str(alert["intelDocId"])],
                            },
                        ]
                    )
                    if external_reference is not None:
                        entity = self.helper.api.stix_domain_object.read(
                            filters=[
                                {
                                    "key": "hasExternalReference",
                                    "values": [external_reference["id"]],
                                }
                            ]
                        )
                        if entity is None:
                            entity = self.helper.api.stix_cyber_observable.read(
                                filters=[
                                    {
                                        "key": "hasExternalReference",
                                        "values": [external_reference["id"]],
                                    }
                                ]
                            )
                        if entity is not None:
                            self.helper.api.stix_sighting_relationship.create(
                                fromId=entity["id"],
                                toId=self.identity["id"],
                                first_seen=parse(alert["createdAt"]).strftime(
                                    "%Y-%m-%dT%H:%M:%SZ"
                                ),
                                last_seen=parse(alert["createdAt"]).strftime(
                                    "%Y-%m-%dT%H:%M:%SZ"
                                ),
                                count=1,
                                confidence=85,
                            )
            time.sleep(60)
