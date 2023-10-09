# recordedfuture/core/api.py

import requests
import re
from .constants import RECORDED_FUTURE_API_ENDPOINT, DEFAULT_HEADER, DATASET
from .utils import configure_logger
from concurrent.futures import ThreadPoolExecutor
from itertools import chain

LOGGER = configure_logger(__name__)


def _is_valid_token(token):
    """Check if the given string is a valid token."""
    return bool(re.match(r"^[a-fA-F0-9]{32}$", token))


class RecordedFutureClient:
    def __init__(self, api_token, labels):
        if not _is_valid_token(api_token):
            raise ValueError("API token is not a valid token.")
        self.api_token = api_token
        self.labels    = labels
        self.headers = DEFAULT_HEADER.copy()
        self.headers["x-rftoken"] = self.api_token

    def _request_data(self, path):
        """Internal method to handle API requests."""
        try:
            response = requests.get(
                url=RECORDED_FUTURE_API_ENDPOINT,
                headers=self.headers,
                params={"path": path},
            )

            LOGGER.info(
                f"HTTP Get Request to endpoint ({RECORDED_FUTURE_API_ENDPOINT}) for path ({path})"
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            LOGGER.error(f"Error while fetching data from {path}: {str(e)}")
            return None

    def fetch_data(self, dataset_key):
        """Fetch data for a given dataset key."""
        # Step 1: Check if dataset_key exists in DATASET
        dataset = DATASET.get(dataset_key)
        if not dataset:
            LOGGER.error(f"No dataset configuration found for key: {dataset_key}")
            return None

        # Step 2: Check if a valid associated path exists
        path = dataset.get("path")
        if not path:
            LOGGER.error(f"No path found for dataset key: {dataset_key}")
            return None

        return self._request_data(path)

    def fetch_data_bundle_transform(self, dataset_key, connect_confidence_level, days_threshold=None):
        """Fetch data for a given dataset key."""

        def transform_dataset(data_set):
            return transformer.transform_to_stix(data_set)

        dataset_info = DATASET.get(dataset_key)
        if not dataset_info:
            LOGGER.error(f"No dataset found for key: {dataset_key}")
            return None

        data = self.fetch_data(dataset_key)
        if not data:
            return None

        # Transform data to STIX format if a transformer is defined for the dataset
        transformer = dataset_info.get("transformer")
        # Set STIX labels
        transform_labels = dataset_info.get("labels").split(',')
        transform_labels.extend(self.labels)
        transformer.set_stix_labels(stix_labels=transform_labels)
        transformer.set_confidence_level(connect_confidence_level=connect_confidence_level)
        LOGGER.info(
            f"Transforming data for ({dataset_key}) with transform ({transformer.__class__.__name__}) and labels ({transformer.stix_labels})."
        )
        
        if transformer:
            with ThreadPoolExecutor() as executor:
                data_to_process = data["results"] if "results" in data else data
                LOGGER.info(f'Total objects to process ({len(data_to_process)})')
                if transformer.filter_data_by_days_ago(data_list=data_to_process, days_ago=days_threshold):
                    stix_objects = [obj for obj in chain.from_iterable(
                        executor.map(
                            transform_dataset,
                            transformer.filtered_data_set
                            )
                        ) if obj]
                else:
                    LOGGER.warning('Filtering data failed.')
                del data
                del data_to_process

                LOGGER.info(f'Total objects to process returned after transform ({len(stix_objects)})')
                return stix_objects
        else:
            # If no transformer is associated, simply return the raw data (or handle as needed)
            return None
