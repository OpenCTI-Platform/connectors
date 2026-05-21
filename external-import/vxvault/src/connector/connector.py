import re
import ssl
import sys
import urllib.request
from datetime import datetime, timezone

import stix2
from connector.settings import ConnectorSettings
from pycti import Identity, OpenCTIConnectorHelper
from stix2 import TLP_WHITE, URL, Bundle


class VXVault:
    """
    VXVault external import connector.

    Fetches URLs of potential malicious payloads from VX Vault and imports them
    as STIX URL observables into OpenCTI.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.author = stix2.Identity(
            id=Identity.generate_id(name="VX Vault", identity_class="organization"),
            name="VX Vault",
            identity_class="organization",
            description="VX Vault is providing URLs of potential malicious payload.",
            external_references=[
                stix2.ExternalReference(
                    source_name="External Source",
                    url="http://vxvault.net",
                    description="VX Vault is providing URLs of potential malicious payload.",
                )
            ],
        )

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence.
        Fetches the VXVault URL list, parses it, and sends STIX bundles to OpenCTI.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )
        work_id = None
        try:
            now = datetime.now(timezone.utc)
            friendly_name = "VXVault run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            if work_id is None:
                self.helper.connector_logger.error(
                    "Failed to initiate work for connector run."
                )
                return

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            ctx = ssl.create_default_context()
            if not self.config.vxvault.ssl_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            response = urllib.request.urlopen(
                self.config.vxvault.url,
                context=ctx,
            )
            data = response.read().decode("utf-8", errors="replace")

            count = 0
            bundle_objects = [self.author]
            for line in data.splitlines():
                count += 1
                if count <= 3:
                    continue
                line = line.strip()
                # Skip HTML tags
                if re.search(r"^<\/?\w+>", line):
                    continue
                # Skip blank lines
                if re.search(r"^\s*$", line):
                    continue
                stix_observable = URL(
                    value=line,
                    object_marking_refs=[TLP_WHITE],
                    custom_properties={
                        "description": "VX Vault URL",
                        "x_opencti_score": 80,
                        "created_by_ref": self.author["id"],
                        "x_opencti_create_indicator": self.config.vxvault.create_indicators,
                    },
                )
                bundle_objects.append(stix_observable)

            bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(
                bundle,
                update=False,
                work_id=work_id,
            )
            self.helper.connector_logger.info(
                "Sending STIX objects to OpenCTI...",
                {"bundles_sent": str(len(bundles_sent))},
            )

            message = f"{self.helper.connect_name} connector successfully run"
            self.helper.api.work.to_processed(work_id, message)
            work_id = None
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            if work_id is not None:
                self.helper.api.work.to_processed(
                    work_id, "Connector stopped by user", in_error=True
                )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler.
        Uses the pycti connector helper scheduler with ISO-8601 duration period.
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
