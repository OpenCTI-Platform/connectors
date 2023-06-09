import yaml
import os
import requests
from pycti import OpenCTIApiClient
from .zerofox_fetchers import fetch_data_from_zerofox_endpoint
from .stix_converter import convert_to_stix_botnet

class ZeroFoxConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        print("Initializing ZeroFoxConnector...")
        config_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.yml')
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        # ZeroFOX API credentials
        self.zerofox_username = config['zerofox']['username']
        self.zerofox_password = config['zerofox']['password']

        self.helper = OpenCTIApiClient(
            url=config['opencti']['url'],
            token=config['opencti']['token']
        )

    def get_access_token(self):
        # Prepare the payload
        payload = {
            "username": self.zerofox_username,
            "password": self.zerofox_password
        }

        # Specify the headers
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        # Send the POST request
        response = requests.post('https://api.zerofox.com/auth/token/', json=payload, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            response_json = response.json()
            access_token = response_json.get('access', None)

            if not access_token:
                raise Exception('Access token not found in response')

            return access_token
        else:
            raise Exception(f'Request failed with status code {response.status_code}, response: {response.text}')

    def upload_stix_bundle_to_opencti(self, stix_bundle):
        # Import the STIX bundle to OpenCTI
        self.helper.stix2.import_bundle_from_json(stix_bundle)

    def run(self, endpoint):
        access_token = self.get_access_token()
        all_json_data = fetch_data_from_zerofox_endpoint(
            access_token, endpoint, self.upload_stix_bundle_to_opencti
        )
