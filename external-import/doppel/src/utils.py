import time
import yaml
import logging
import requests
from tenacity import retry, stop_after_attempt, wait_fixed

# Load Configurations
def load_config():
    with open("config/config.yaml", "r") as f:
        return yaml.safe_load(f)

# Retry Failed API Calls
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def make_api_request(url, headers):
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

# Format Time to STIX
def format_time(timestamp):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
