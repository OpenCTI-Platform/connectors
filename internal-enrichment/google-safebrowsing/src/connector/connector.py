import requests
from connector.settings import ConnectorSettings
from pycti import CustomObservableHostname, OpenCTIConnectorHelper
from stix2 import URL, DomainName

SUPPORTED_ENTITY_TYPES = ("Domain-Name", "Url", "Hostname")


class SafeBrowsingConnector:
    """Internal enrichment connector for Google/Yandex Safe Browsing.

    Checks Domain-Name, Url and Hostname observables against the Safe Browsing
    API and, when a match is found, updates the observable score, description
    and labels in OpenCTI.

    Attributes:
        config (ConnectorSettings): The connector configuration.
        helper (OpenCTIConnectorHelper): The helper to use.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """Initialize `SafeBrowsingConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector.
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI.
        """
        self.config = config
        self.helper = helper

    def google_safe_browsing(self, observable: dict) -> str | None:
        """Checks an observable against the configured Safe Browsing API (Google or Yandex)."""
        self.helper.connector_logger.info(
            "Checking observable against Safe Browsing",
            {"value": observable["value"]},
        )

        api_key = self.config.safe_browsing.api_key.get_secret_value()
        api_url = str(self.config.safe_browsing.api_url)
        domain = observable["value"]
        stix_objects = []
        url = f"{api_url.rstrip('/')}/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "testing",  # A descriptive name for your client
                "clientVersion": "1.0",  # Version of your application
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "THREAT_TYPE_UNSPECIFIED",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": [
                    "URL",
                    "EXECUTABLE",
                    "THREAT_ENTRY_TYPE_UNSPECIFIED",
                ],
                "threatEntries": [{"url": domain}],
            },
        }
        try:
            response = requests.post(
                url,
                json=payload,
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            # A timeout / connection error / etc. must not crash the enrichment
            # worker; log it and treat it as an error (no-match) path.
            # The request URL carries the API key: never log it in clear.
            self.helper.connector_logger.error(
                "Safe Browsing request failed",
                {"error": str(e).replace(api_key, "**********")},
            )
            return None
        if response.status_code == 200:
            if response.json():
                if observable.get("x_opencti_description") is None:
                    existing_description = ""
                else:
                    existing_description = (
                        observable.get("x_opencti_description") + "\\n"
                    )

                safe_browsing_output = response.json()

                first_output = safe_browsing_output.get("matches")[0]

                observable_description = f"Domain flagged by Safe Browsing \n + Threat Type: {first_output.get('threatType')} \n + Platform Type: {first_output.get('platformType')} \n + Threat Entry Type: {first_output.get('threatEntryType')} \n \n"
                if observable["entity_type"] == "Domain-Name":
                    new_domain_object = DomainName(
                        id=observable["standard_id"],
                        value=observable["value"],
                        custom_properties={
                            "x_opencti_description": existing_description
                            + observable_description,
                            "x_opencti_score": 100,
                        },
                    )
                    stix_objects.append(new_domain_object)
                elif observable["entity_type"] == "Url":
                    new_url_object = URL(
                        id=observable["standard_id"],
                        value=observable["value"],
                        custom_properties={
                            "x_opencti_description": existing_description
                            + observable_description,
                            "x_opencti_score": 100,
                        },
                    )
                    stix_objects.append(new_url_object)

                elif observable["entity_type"] == "Hostname":
                    new_hostname_object = CustomObservableHostname(
                        id=observable["standard_id"],
                        value=observable["value"],
                        custom_properties={
                            "x_opencti_description": existing_description
                            + observable_description,
                            "x_opencti_score": 100,
                        },
                    )

                    stix_objects.append(new_hostname_object)

                # creating a bundle
                bundles_sent = self._send_bundle(stix_objects)
                self.helper.api.stix_cyber_observable.add_label(
                    id=observable["id"], label_name=first_output.get("threatType")
                )
                self.helper.connector_logger.info(
                    "Bundles sent to OpenCTI", {"bundles_sent": len(bundles_sent)}
                )
                return f"Sent {len(bundles_sent)} bundles to OpenCTI"

        else:
            self.helper.connector_logger.error(
                "Error checking observable against Safe Browsing",
                {"status_code": response.status_code},
            )

        return None

    def _entity_in_scope(self, data: dict) -> bool:
        """Check that the entity type (from its STIX id) is in the connector scope."""
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data["entity_id"].split("--")[0].lower()
        return entity_type in scopes

    def _is_tlp_allowed(self, opencti_entity: dict) -> bool:
        """Check that the entity TLP is lower than or equal to the configured max TLP."""
        tlp = None
        for marking_definition in opencti_entity.get("objectMarking") or []:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        return self.helper.check_max_tlp(
            tlp, f"TLP:{self.config.connector.max_tlp.upper()}"
        )

    def _send_bundle(self, stix_objects: list) -> list:
        """Create a STIX bundle from the given objects and send it to OpenCTI."""
        stix_bundle = self.helper.stix2_create_bundle(stix_objects)
        return self.helper.send_stix2_bundle(
            stix_bundle, cleanup_inconsistent_bundle=True
        )

    def process_message(self, data: dict) -> str | None:
        """Processing the enrichment request

        Args:
            data (dict): The data to process. The `enrichment_entity` attribute contains the object to enrich.
        """
        opencti_entity = data["enrichment_entity"]

        if (
            not self._entity_in_scope(data)
            or opencti_entity["entity_type"] not in SUPPORTED_ENTITY_TYPES
        ):
            if not data.get("event_type"):
                # Playbook trigger: send the original bundle back unchanged
                self._send_bundle(data["stix_objects"])
                return "Entity out of scope, original bundle sent back"
            self.helper.connector_logger.warning(
                "Entity is not in the connector scope, skipping",
                {
                    "entity_id": data["entity_id"],
                    "entity_type": opencti_entity["entity_type"],
                },
            )
            return None

        if not self._is_tlp_allowed(opencti_entity):
            self.helper.connector_logger.warning(
                "Entity TLP is greater than the connector max TLP, skipping",
                {
                    "entity_id": data["entity_id"],
                    "max_tlp": self.config.connector.max_tlp,
                },
            )
            return None

        # google_safe_browsing() already logs a single "Checking ... against Safe
        # Browsing" line for every supported type, so don't log again here.
        return self.google_safe_browsing(opencti_entity)

    def run(self) -> None:
        """Listen to enrichment requests sent by OpenCTI."""
        self.helper.listen(message_callback=self.process_message)
