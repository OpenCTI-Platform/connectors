import json
import logging
import os
from datetime import datetime, timedelta

import requests
from requests import RequestException

log = logging.getLogger("mitre_ttps")


class MitreTtpDownloader:
    """
    Downloads MITRE ATT&CK TTPs from
    https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    and formats them for use in the rstcloud connector.

    Functionality:
        1. Creates a new JSON file mapping TTP IDs to their names for quick lookup.
        2. Removes all objects that are not of type 'attack-pattern'.
        3. Saves the mapping file to the same directory as the rstcloud connector.
        4. On each run interval, checks if a new mapping is available and downloads it if so.
        5. Adds new mappings to the existing mapping file.
        6. If the mapping file exists and is older than 3 days, attempts to pull a new file.
    """

    def __init__(self, conf):
        self.conf = conf

    def download_mitre_ttps(self):
        """Download and process MITRE ATT&CK TTPs, creating a mapping file."""
        output_file = "mitre_ttp_mapping.json"
        output_file = os.path.join(os.path.dirname(__file__), output_file)

        # Check if file exists and is less than 3 days old
        if os.path.exists(output_file):
            file_time = datetime.fromtimestamp(os.path.getmtime(output_file))
            if datetime.now() - file_time < timedelta(days=3):
                log.info("MITRE TTP mapping file is up to date, skipping download")
                return output_file

        log.info("Downloading MITRE ATT&CK TTPs...")

        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            output_data = {}
            external_id = None

            # Parse the data to extract attack patterns
            for x in data.get("objects", []):
                # Check if the 'type' of the object is 'attack-pattern'
                if x.get("type") == "attack-pattern":
                    # Reset external_id for each object
                    external_id = None

                    # Find the external_references
                    external_references = x.get("external_references", [])
                    for ref in external_references:
                        if ref.get("source_name") == "mitre-attack":
                            external_id = ref.get("external_id")
                            break

                    if external_id:
                        output_data[external_id] = x.get("name")
                        log.debug(
                            "Added TTP mapping: %s -> %s", external_id, x.get("name")
                        )

            # Load existing data if file exists
            existing_data = {}
            if os.path.exists(output_file):
                try:
                    with open(output_file, "r", encoding="utf-8") as f:
                        existing_data = json.load(f)
                    log.info("Loaded %d existing TTP mappings", len(existing_data))
                except (json.JSONDecodeError, IOError) as e:
                    log.warning("Could not load existing mapping file: %s", e)

            # Merge new data with existing data
            existing_data.update(output_data)

            # Save the updated mapping
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)

            log.info(
                "Successfully updated MITRE TTP mapping file with %d new mappings",
                len(output_data),
            )
            log.info("Total mappings in file: %d", len(existing_data))

            return output_file

        except RequestException as e:
            log.error("Failed to download MITRE ATT&CK data: %s", e)
            raise
        except json.JSONDecodeError as e:
            log.error("Failed to parse MITRE ATT&CK JSON data: %s", e)
            raise
        except Exception as e:
            log.error("Unexpected error downloading MITRE TTPs: %s", e)
            raise

    def load_ttp_mapping(self):
        """Load the TTP mapping from the local file."""
        output_file = "mitre_ttp_mapping.json"
        output_file = os.path.join(os.path.dirname(__file__), output_file)

        if not os.path.exists(output_file):
            log.warning("MITRE TTP mapping file does not exist")
            return {}

        try:
            with open(output_file, "r", encoding="utf-8") as f:
                mapping = json.load(f)
            log.info("Loaded %d TTP mappings from file", len(mapping))
            return mapping
        except (json.JSONDecodeError, IOError) as e:
            log.error("Failed to load TTP mapping file: %s", e)
            return {}
