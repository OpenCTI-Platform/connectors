import requests

from .stix_converter import (
    convert_to_stix_botnet,
    convert_to_stix_malware,
    convert_to_stix_ransomware,
)


def fetch_data_from_zerofox_endpoint(access_token, endpoint, upload_function):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + access_token,
    }

    endpoint_url = "https://api.zerofox.com/cti/" + endpoint
    cti_json_data = []

    while endpoint_url is not None:
        print(f"Hitting endpoint: {endpoint_url}")  # print the endpoint being hit
        response = requests.get(endpoint_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if data and "results" in data and data["results"]:
                for item in data["results"]:
                    print("Processing item:", item)
                    if endpoint == "botnet":
                        try:
                            converted_item = convert_to_stix_botnet(
                                item
                            )  # Convert the item using the converter function
                            upload_function(
                                converted_item
                            )  # Upload the converted item to OpenCTI
                            cti_json_data.append(
                                item
                            )  # Append the raw JSON item to the list
                        except Exception as e:
                            print(f"Error in converting or pushing item: {e}")
                    elif endpoint == "malware":
                        # Handle the malware endpoint differently
                        try:
                            converted_item = convert_to_stix_malware(item)
                            print(item)
                            upload_function(converted_item)
                            cti_json_data.append(
                                item
                            )  # Append the raw JSON item to the list
                        except Exception as e:
                            print(f"Error in processing item for malware endpoint: {e}")
                    elif endpoint == "ransomware":
                        # Handle the malware endpoint differently
                        try:
                            converted_item = convert_to_stix_ransomware(item)
                            print(item)
                            upload_function(converted_item)
                            cti_json_data.append(
                                item
                            )  # Append the raw JSON item to the list
                        except Exception as e:
                            print(f"Error in processing item for malware endpoint: {e}")
            else:
                print("JSON data objects are empty")
                endpoint_url = None  # No more pages to fetch
            endpoint_url = data.get("next")  # Retrieve the next page URL
        else:
            raise Exception(
                f"Request failed with status code {response.status_code}, response: {response.text}"
            )

    return cti_json_data
