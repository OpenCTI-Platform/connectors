import sys
import traceback

from lib.ransom_conn import RansomwareAPIConnector


class CustomConnector(RansomwareAPIConnector):
    def _collect_intelligence(self) -> []:
        """Collects intelligence from channels

        Aadd your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects."""

        raise NotImplementedError("This method has not been implemented yet")


if __name__ == "__main__":
    try:
        connector = CustomConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
