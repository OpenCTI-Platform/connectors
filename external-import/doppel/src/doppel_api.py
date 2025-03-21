import requests
import yaml
from logger import get_logger

logger = get_logger(__name__)



with open("config/config.yaml", "r") as f:
    config = yaml.safe_load(f)


DOPPEL_API_URL = config["doppel_api"]["url"]
API_KEY = config["doppel_api"]["api_key"]

print("doppel hii")

def fetch_alerts():
    print("Starting fetch_alerts()...")  # Debug print

    headers = {"x-api-key": API_KEY, "accept": "application/json"}
    print(f"Using API Key: {API_KEY[:5]}********")  # Mask API key for security
    print(f"Sending request to {DOPPEL_API_URL}...")  

    try:
        response = requests.get(DOPPEL_API_URL, headers=headers)
        print(f"Received response with status code: {response.status_code}")

        if response.status_code == 200:
            print("Successfully fetched alerts from Doppel API.")
            logger.info("Successfully fetched alerts from Doppel API.")
            return response.json()
        else:
            print(f"API returned error: {response.status_code}, Response: {response.text}")
            logger.error(f"Error fetching alerts: {response.status_code}, Response: {response.text}")
            return None
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        logger.error(f"Exception in fetch_alerts: {str(e)}")
        return None

