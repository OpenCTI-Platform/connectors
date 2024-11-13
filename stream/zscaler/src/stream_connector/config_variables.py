import os
from dotenv import load_dotenv
import yaml

load_dotenv()


with open("/opt/opencti-connector-zscaler/config.yml", "r") as stream:
    config = yaml.safe_load(stream)

ZSCALER_USERNAME = os.getenv("ZSCALER_USERNAME")
ZSCALER_PASSWORD = os.getenv("ZSCALER_PASSWORD")
ZSCALER_API_KEY = os.getenv("ZSCALER_API_KEY")


OPENCTI_URL = config.get('opencti', {}).get('url', '')
OPENCTI_TOKEN = config.get('opencti', {}).get('token', '')
SSL_VERIFY = config.get('opencti', {}).get('ssl_verify', True)