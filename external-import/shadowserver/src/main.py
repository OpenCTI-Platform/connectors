# import os
import os
import sys
import time

from datetime import datetime, timedelta
from lib.external_import import ExternalImportConnector
from shadowserver import ShadowServerAPI

# Lookback in days
LOOKBACK = 3
INITIAL_LOOKBACK = 30

class CustomConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector"""
        super().__init__()
        # TODO: Raise errors for missing environment variables, or incorrect values.
        self.api_key = os.environ.get("SHADOWSERVER_API_KEY", None)
        self.api_secret = os.environ.get("SHADOWSERVER_API_SECRET", None)
        self.marking = os.environ.get("SHADOWSERVER_MARKING", None)
        self.first_run = True
        self.lookback = LOOKBACK
        self.now = datetime.now()

        # Get last run state or set the initial date.
        self.current_state = self.helper.get_state()
        if self.current_state and "last_run" in self.current_state:
            self.first_run = False
        else:
            self.lookback = INITIAL_LOOKBACK
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

        if subscription_list and isinstance(subscription_list, list):
            for subscription in subscription_list:
                for days_lookback in range(self.lookback, -1, -1):
                    date = self.now - timedelta(days=days_lookback)
                    date_str = date.strftime("%Y-%m-%d")
                    report_list = shadowserver_api.get_report_list(
                        date=date_str, type=subscription
                    )

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
