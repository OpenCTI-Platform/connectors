import threading
import time
from datetime import datetime
from urllib import parse

from .constants import THREAT_MAP_TYPE_MAPPER


class ThreatMap(threading.Thread):
    def __init__(self, helper, rfapi, tlp, risk_list_threshold):
        threading.Thread.__init__(self)
        self.helper = helper
        self.rfapi = rfapi
        self.tlp = tlp
        self.risk_list_threshold = risk_list_threshold

    def run(self):
        threat_maps = self.rfapi.get_threat_maps()

        timestamp = int(time.time())
        now = datetime.utcfromtimestamp(timestamp)

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            "Recorded Future Threat Map run @ " + now.strftime("%Y-%m-%d %H:%M:%S"),
        )

        self.helper.log_info("[THREAT MAPS] Pulling threat maps entities...")

        for threat_map in threat_maps:
            threat_map_url = parse.quote(threat_map["url"], safe="/")
            entities_mapped = self.rfapi.get_entities_mapped(threat_map_url)
            entities_mapped_ids = []

            for entity_mapped in entities_mapped:
                # Create a list of all entities in threat map
                entities_mapped_ids.append(entity_mapped["id"])

            info_msg = (
                f"[THREAT MAPS] Getting {len(entities_mapped_ids)} entities for"
                f" {threat_map['type']} threat map and links entities..."
            )
            self.helper.log_info(info_msg)

            # Getting all entities (TA or Malware) with their links
            entities_mapped_with_links = self.rfapi.get_entities_links(
                entities_mapped_ids
            )

            if entities_mapped_with_links is not None:

                total_mapped_entities = len(entities_mapped_ids)

                for entity_with_links in entities_mapped_with_links:
                    for key, threat_map_type in THREAT_MAP_TYPE_MAPPER.items():
                        if threat_map["type"] == key:
                            # Convert into stix object
                            _name = entity_with_links["entity"]["name"]
                            _type = entity_with_links["entity"]["type"].replace(
                                "type:", ""
                            )
                            entity_to_stix2 = threat_map_type["class"](
                                _name, _type, tlp=self.tlp
                            )

                            # Map data with related entities
                            entity_to_stix2.map_data(entity_with_links, self.tlp)

                            # Create bundle
                            entity_to_stix2.build_bundle(entity_to_stix2)
                            bundle = entity_to_stix2.to_stix_bundle()

                            self.helper.log_info(
                                "[THREAT MAPS] Sending Bundle to server with "
                                + str(len(bundle.objects))
                                + " objects"
                            )

                            total_mapped_entities -= 1

                            self.helper.log_info(
                                "[THREAT MAPS] Remaining "
                                + str(total_mapped_entities)
                                + " entities with their links to import for "
                                + threat_map["type"]
                                + " threat map"
                            )

                            # Send stix bundle for ingestion
                            self.helper.send_stix2_bundle(
                                bundle.serialize(),
                                work_id=work_id,
                            )

        self.helper.set_state({"last_threat_map_run": timestamp})
        message = (
            f"{self.helper.connect_name} connector successfully run for Threat Maps"
        )
        self.helper.api.work.to_processed(work_id, message)
