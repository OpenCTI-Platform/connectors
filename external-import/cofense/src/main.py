import os
import sys
import time
import traceback
from datetime import datetime, timedelta
from typing import Any

import stix2
import yaml
from cofense_intelligence import CFIntelSync, CofenseIntegration, MalwareThreatReport
from pycti import (
    Identity,
    Incident,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)

config_file_path = os.getenv(
    "OPENCTI_CONFIG", os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
)
config = (
    yaml.load(open(config_file_path), Loader=yaml.FullLoader)
    if os.path.isfile(config_file_path)
    else {}
)
helper = OpenCTIConnectorHelper(config)
interval_sec = get_config_variable(
    "COFENSEINTEL_INTERVAL", ["cofense", "interval"], config, True
)
user_token = get_config_variable(
    "COFENSEINTEL_USER", ["cofense", "user"], config, False
)
user_pass = get_config_variable(
    "COFENSEINTEL_PASSWORD", ["cofense", "password"], config, False
)
update_existing_data = get_config_variable(
    "COFENSEINTEL_UPDATE", ["cofense", "update_existing_data"], config, False
)

BLOCK_TYPE = {
    "URL": "url",
    "Domain Name": "domain-name",
    "IPv4 Address": "ipv4-addr",
    "Email": "email-addr",
}

BLOCK_OBJ = {
    "URL": stix2.URL,
    "Domain Name": stix2.DomainName,
    "IPv4 Address": stix2.IPv4Address,
    "Email": stix2.EmailAddress,
}


class CofenseIntel(CofenseIntegration):

    def _get_labels(self, mrti: MalwareThreatReport) -> list:
        labels = []

        labels.extend(f"family:{x}" for x in mrti.malware_families)
        labels.extend(f"delivery:{x}" for x in mrti.delivery_mechs)
        labels.extend(f"brand:{x}" for x in mrti.brands)

        return labels

    def _create_incident(
        self,
        mrti: MalwareThreatReport,
        author_id: str,
        mrti_labels: list,
        created: datetime,
    ) -> Incident:
        incident = stix2.Incident(
            id=Incident.generate_id(mrti.label, created),
            name=mrti.label,
            description=f"{mrti.label}\n{mrti.executive_summary}",
            object_marking_refs=[stix2.TLP_RED],  # TODO: Is this correct?
            labels=mrti_labels,
            created_by_ref=author_id,
        )

        return incident

    def _get_observable_from_block(
        self, block: Any, author_id: str, threat_id: int, mrti_labels: list
    ) -> Any:
        labels = [f"related-{x}" for x in mrti_labels]
        labels.append(f"family:{block.malware_family}")
        if block.delivery_mech:
            labels.append(f"delivery:{block.delivery_mech}")
        custom_properties = {
            "labels": labels,
            "x_opencti_score": 100,
            "x_opencti_created_by_ref": author_id,
            "description": f"From Cofense Intelligence Threat Report {threat_id}",
            "x_opencti_create_indicator": True,
        }

        observable_obj = BLOCK_OBJ[block.block_type]

        return observable_obj(
            type=BLOCK_TYPE[block.block_type],
            value=block.watchlist_ioc,
            custom_properties=custom_properties,
        )

    def _get_observable_from_executable_set(
        self, executable: Any, author_id: str, threat_id: int, mrti_labels: list
    ) -> Any:

        labels = [f"related-{x}" for x in mrti_labels]
        labels.append(f"family:{executable.malware_family}")

        custom_properties = {
            "labels": labels,
            "x_opencti_score": 100,
            "x_opencti_created_by_ref": author_id,
            "description": f"From Cofense Intelligence Threat Report {threat_id}",
            "x_opencti_create_indicator": True,
        }

        if executable.delivery_mech:
            labels.append(f"delivery:{executable.delivery_mech}")
        file_obj = stix2.File(
            name=executable.file_name,
            type="file",
            hashes={
                "MD5": str(executable.md5),
                **({"SHA-1": str(executable.sha1)} if executable.sha1 else {}),
                **({"SHA-256": str(executable.sha256)} if executable.sha256 else {}),
                **({"SHA-512": str(executable.sha512)} if executable.sha512 else {}),
            },
            custom_properties=custom_properties,
        )

        return file_obj

    def process(self, mrti):
        """
        :param mrti:
        :type mrti: MalwareThreatReport
        :return:
        """

        helper.log_info("Fetching knowledge...")
        author = stix2.Identity(
            id=Identity.generate_id("Cofense", "organization"),
            type="identity",
            name="Cofense",
            identity_class="organization",
            description="CofenseIntel",
            confidence=helper.connect_confidence_level,
        )

        now = datetime.utcnow()
        friendly_name = "CofenseIntel run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
        work_id = helper.api.work.initiate_work(helper.connect_id, friendly_name)

        stix_objs = [author]

        # indicators = []

        mrti_labels = self._get_labels(mrti=mrti)
        created_at = mrti.first_published
        incident_stix = self._create_incident(
            mrti=mrti,
            author_id=author["id"],
            mrti_labels=mrti_labels,
            created=created_at,
        )
        stix_objs.append(incident_stix)

        # custom_properties = {
        #     # "description": description,
        #     # "labels": labels,
        #     "x_opencti_score": 100,
        #     "x_opencti_created_by_ref": author['id'],
        #     "x_opencti_description": f'{mrti.threat_id}',
        # }

        for block in mrti.block_set:
            stix_observable = self._get_observable_from_block(
                block=block,
                mrti_labels=mrti_labels,
                author_id=author["id"],
                threat_id=mrti.threat_id,
            )
            stix_objs.append(stix_observable)

            incident_relation = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", stix_observable.id, incident_stix.id
                ),
                relationship_type="related-to",
                created_by_ref=author["id"],
                source_ref=stix_observable.id,
                target_ref=incident_stix.id,
                object_marking_refs=[stix2.TLP_RED],
                allow_custom=True,
            )

            stix_objs.append(incident_relation)

        for executable in mrti.executable_set:
            stix_observable = self._get_observable_from_executable_set(
                executable=executable,
                author_id=author["id"],
                threat_id=mrti.threat_id,
                mrti_labels=mrti_labels,
            )
            stix_objs.append(stix_observable)

            incident_relation = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", stix_observable.id, incident_stix.id
                ),
                relationship_type="related-to",
                created_by_ref=author["id"],
                source_ref=stix_observable.id,
                target_ref=incident_stix.id,
                object_marking_refs=[stix2.TLP_RED],
                allow_custom=True,
            )

            stix_objs.append(incident_relation)

        message = f"Processed ThreatID: {mrti.threat_id}"
        helper.log_info(message)
        bundle = stix2.Bundle(*stix_objs, allow_custom=True)
        self._send_bundle(bundle, work_id=work_id)
        # self._send_bundle(bundle)

    def _send_bundle(self, bundle: stix2.Bundle, work_id=None):
        serialized_bundle = bundle.serialize()
        helper.send_stix2_bundle(
            serialized_bundle, work_id=work_id, update=update_existing_data
        )
        timestamp = int(time.time())
        helper.set_state({"last_run": timestamp})
        message = f"Last_run stored, next run in: {round(interval_sec / 60, 2)} minutes"
        helper.api.work.to_processed(work_id, message)

    # def _send_bundle(self, bundle: stix2.Bundle):
    #     serialized_bundle = bundle.serialize()
    #     print(serialized_bundle)


def get_position() -> tuple:
    try:
        with open("cf_intel.pos", "r") as f:
            position = f.read().strip()
            if position:
                return position, None
    except Exception as e:
        helper.log_warning("No position found, defaulting to 30 days ago", e)

    init_date = int((datetime.utcnow() - timedelta(days=30)).timestamp())
    return None, init_date


if __name__ == "__main__":
    try:
        while True:
            try:
                timestamp = int(time.time())
                current_state = helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    helper.log_info("Connector has never run")

                if last_run is None or (
                    (timestamp - last_run) > (int(interval_sec) - 1)
                ):

                    position, init_date = get_position()
                    connector = CFIntelSync(
                        CF_USER=user_token,
                        CF_PASS=user_pass,
                        INTEGRATION=CofenseIntel,
                        JITTER=False,
                        USE_LOCK=False,
                        INIT_DATE=init_date,
                        POSITION=position,
                    )
                    connector.run()

                else:
                    new_interval = interval_sec - (timestamp - last_run)
                    helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60, 2))
                        + " minutes"
                    )

                time.sleep(interval_sec)
            except (KeyboardInterrupt, SystemExit):
                helper.log_info("CofenseIntel connector stopping...")
                sys.exit(0)

            except Exception as e:  # noqa: B902
                helper.log_info(f"CofenseIntel connector internal error: {e}")

                if helper.connect_run_and_terminate:
                    helper.log_info("Connector stop")
                    sys.exit(0)
    except Exception:
        traceback.print_exc()
        exit(1)
