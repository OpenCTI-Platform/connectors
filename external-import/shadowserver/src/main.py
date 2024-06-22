# import os
import sys
import time
import os
from lib.external_import import ExternalImportConnector

from shadowserver import ShadowServerAPI


class CustomConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector
        """
        super().__init__()
        # TODO: Raise errors for missing environment variables, or incorrect values.
        self.api_key = os.environ.get("SHADOWSERVER_API_KEY", None)
        self.api_secret = os.environ.get("SHADOWSERVER_API_SECRET", None)
        self.marking = os.environ.get("SHADOWSERVER_MARKING", None)
        # TODO: Add interval (Look back X days).

    def _collect_intelligence(self) -> []:
        """Collects intelligence from channels

        Aadd your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_info(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        stix_objects = []

        # ===========================
        # === Add your code below ===
        # ===========================
        shadowserver_api = ShadowServerAPI(
            api_key=self.api_key,
            api_secret=self.api_secret,
            marking_refs=self.marking,
        )

        # Get support Report types
        subscription_list = shadowserver_api.get_subscriptions()
        self.helper.log_info(f"Available report types: {subscription_list}.")

        for subscription in subscription_list:
            # TODO: Need to handle date, potentially also address paging for lists? 
            report_list = shadowserver_api.get_report_list(date='2024-06-20', type=subscription)

            self.helper.log_debug(f"Found {len(report_list)} reports.")
            for report in report_list:
                report_stix_objects = shadowserver_api.get_stix_report(
                        report=report,
                        api_helper=self.helper,
                    )
                
                # Filter out duplicates and append to stix_objects.
                for stix_object in report_stix_objects:
                    if stix_object not in stix_objects and stix_object:
                        stix_objects.append(stix_object)

        # ===========================
        # === Add your code above ===
        # ===========================

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects


if __name__ == "__main__":
    try:
        connector = CustomConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
