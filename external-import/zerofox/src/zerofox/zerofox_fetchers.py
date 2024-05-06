from datetime import datetime, timedelta
from pycti import OpenCTIConnectorHelper
from zerofox.app.zerofox import ZeroFox
from .stix_converter import (
    convert_to_stix_botnet,
    convert_to_stix_malware,
    convert_to_stix_ransomware,
)


def fetch_data_from_zerofox_endpoint(client :ZeroFox, endpoint, helper: OpenCTIConnectorHelper):
            yesterday = datetime.now() - timedelta(days=1)
            for item in client.fetch_feed(endpoint=endpoint, last_run=yesterday):
                print("Processing item:", item)
                if endpoint == "botnet":
                    try:
                        converted_item = convert_to_stix_botnet(
                            item, helper
                        )  # Convert the item using the converter function

                        helper.send_stix2_bundle(
                            converted_item
                        )  # Upload the converted item to OpenCTI
                    except Exception as e:
                        print(f"Error in converting or pushing item: {e}")
                elif endpoint == "malware":
                    # Handle the malware endpoint differently
                    try:
                        converted_item = convert_to_stix_malware(
                            item, helper)
                        print(item)
                        helper.send_stix2_bundle(converted_item)
                    except Exception as e:
                        print(
                            f"Error in processing item for malware endpoint: {e}")
                elif endpoint == "ransomware":
                    # Handle the malware endpoint differently
                    try:
                        converted_item = convert_to_stix_ransomware(
                            item, helper)
                        print(item)
                        helper.send_stix2_bundle(converted_item)
                    except Exception as e:
                        print(
                            f"Error in processing item for malware endpoint: {e}")
