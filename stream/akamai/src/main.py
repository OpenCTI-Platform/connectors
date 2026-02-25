import os
import sys
import time
import traceback

from pycti import OpenCTIConnectorHelper
from stream_connector.connector import AkamaiConnector


if __name__ == "__main__":
    try:
        # Initialize OpenCTI helper
        # It automatically reads OPENCTI_* variables from environment
        helper = OpenCTIConnectorHelper({})

        # Instantiate connector using environment variables
        connector = AkamaiConnector(
            helper=helper,
            base_url=os.environ["AKAMAI_BASE_URL"],
            client_token=os.environ["AKAMAI_CLIENT_TOKEN"],
            client_secret=os.environ["AKAMAI_CLIENT_SECRET"],
            access_token=os.environ["AKAMAI_ACCESS_TOKEN"],
            client_list_id=os.environ["AKAMAI_CLIENT_LIST_ID"],
        )

        # Start listening to OpenCTI live stream
        connector.start()

    except Exception:
        # Print full stack trace in case of crash
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)