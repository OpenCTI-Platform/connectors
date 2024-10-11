from datetime import datetime
from typing import Callable

from dateutil import parser as date_parser
import tempfile
import requests
import os
import json
import time
import yaml

from requests import RequestException
from requests.structures import CaseInsensitiveDict
from requests.adapters import HTTPAdapter
from urllib3 import Retry
from requests_toolbelt import sessions

from src import log

TOKEN_URL = "https://oauth.zvelo.io/oauth/token"
retry_strategy = Retry(  # Setting up retries for the Data pull part
    total=10,
    status_forcelist=[401, 403, 429, 500, 502, 503, 504],
    allowed_methods=["GET"]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
zvelo_http = sessions.BaseUrlSession(base_url="https://api.zvelo.io")
zvelo_http.mount("https://", adapter)


class ZveloIngest:

    def __init__(self,
                 response_field: str,
                 start_timestamp: str,
                 end_timestamp: str,
                 endpoint_path: str,
                 stix_translation_function: Callable):
        """
        Schema file is assumed to be in app/resources/pyarrow_schemas
        field_rename_dict: added in as it was requested to rename one of the fields from the feeds. The fields from the api are the keys, the value
        is what they should be renamed to
        """
        self.response_field = response_field
        self.params = {
            'created_date_start': date_parser.parse(start_timestamp).isoformat(),
            'created_date_end': date_parser.parse(end_timestamp).isoformat(),
        }
        self.endpoint_path = endpoint_path
        self.stix_translation_function = stix_translation_function
        self.retrieved_records = 0
        self.page = 0
        self.max_page = None
        self.complete = False
        self.authentication_token = None
        self.fetch_time = datetime.utcnow()
        self.destination_filename = "zvelo_data.ndjson"
        self.config = None  # This is set up in the run method

    def run(self):
        self._load_config()
        with tempfile.TemporaryDirectory() as tmpdir:
            destination_file = os.path.join(tmpdir, self.destination_filename)
            self._retrieve_all_data(destination_file=destination_file)

    def _load_config(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        self.config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        print(self.config)

    def _retrieve_all_data(self, destination_file):
        while not self.complete:
            if not self.authentication_token:  # This needs to be inside the loop as the token expires
                self._set_authentication_token()
            authenticated_headers = CaseInsensitiveDict()
            self.params["page"] = self.page
            authenticated_headers["Authorization"] = f"Bearer {self.authentication_token}"
            with zvelo_http.get(url=self.endpoint_path, headers=authenticated_headers, params=self.params) as response:
                # The zvelo_http object has retry logic added
                try:
                    response.raise_for_status()
                    response_data = json.loads(response.text)
                    threat_info = response_data.get(self.response_field)
                    if not self.max_page:
                        self.max_page = response_data.get("_response_part").get("num_pages")
                    result = []
                    for record in threat_info.get(self.response_field.split("_")[0]):
                        cleaned_record = self.stix_translation_function(record)
                        if cleaned_record: result.append(json.dumps(record))
                    self.retrieved_records += len(result)
                    log.info(f"saving data for page {self.page} of {self.max_page}")
                    # TODO: EXPORT DATA TO OPENCTI VIA API
                except RequestException as e:
                    log.error(f"error retrieving records from Zvelo, exception message = {e}")
                self.page += 1
                self.complete = self.page >= self.max_page

    def _set_authentication_token(self):
        self.token_expiration = int(time.time() + (3600 * 24))
        token_headers = CaseInsensitiveDict()
        token_headers["Content-Type"] = "application/json"
        zvelo_client_id = self.config.get("zveloingest").get("zvelo-client-id")
        zvelo_client_secret = self.config.get("zveloingest").get("zvelo-client-secret")
        data = {"client_id": zvelo_client_id, "client_secret": zvelo_client_secret,
                "audience": "https://api.zvelo.io/v1/",
                "grant_type": "client_credentials"}
        try:
            response = requests.post(TOKEN_URL, headers=token_headers, data=json.dumps(data))
            response.raise_for_status()
        except Exception as e:
            log.error(f"error retrieving access token, exception message = {e}")
            exit(1)

        response_data = json.loads(response.text)
        self.authentication_token = response_data.get("access_token")
