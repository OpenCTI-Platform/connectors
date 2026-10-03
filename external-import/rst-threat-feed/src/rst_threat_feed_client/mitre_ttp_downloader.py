"""Download and cache MITRE ATT&CK technique ID → name mappings."""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict

import requests
from requests import RequestException

log = logging.getLogger("mitre_ttps")


class MitreTtpDownloader:
    """
    Downloads MITRE ATT&CK TTPs from the public enterprise-attack bundle and
    maintains a local ID→name mapping used when create_mitre_ttps is enabled.
    """

    def __init__(self, conf: Dict[str, Any] | None = None) -> None:
        self.conf = conf or {}

    def _mapping_path(self) -> str:
        return os.path.join(os.path.dirname(__file__), "mitre_ttp_mapping.json")

    def download_mitre_ttps(self) -> str:
        """Download and process MITRE ATT&CK TTPs, creating a mapping file."""
        output_file = self._mapping_path()

        if os.path.exists(output_file):
            file_time = datetime.fromtimestamp(os.path.getmtime(output_file))
            if datetime.now() - file_time < timedelta(days=3):
                log.info("MITRE TTP mapping file is up to date, skipping download")
                return output_file

        log.info("Downloading MITRE ATT&CK TTPs...")

        try:
            url = (
                "https://raw.githubusercontent.com/mitre/cti/master/"
                "enterprise-attack/enterprise-attack.json"
            )
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            output_data: Dict[str, str] = {}
            for obj in data.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                external_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        external_id = ref.get("external_id")
                        break
                if external_id:
                    output_data[external_id] = obj.get("name")

            existing_data: Dict[str, str] = {}
            if os.path.exists(output_file):
                try:
                    with open(output_file, "r", encoding="utf-8") as handle:
                        existing_data = json.load(handle)
                    log.info("Loaded %d existing TTP mappings", len(existing_data))
                except (json.JSONDecodeError, OSError) as exc:
                    log.warning("Could not load existing mapping file: %s", exc)

            existing_data.update(output_data)
            with open(output_file, "w", encoding="utf-8") as handle:
                json.dump(existing_data, handle, indent=2, ensure_ascii=False)

            log.info(
                "Successfully updated MITRE TTP mapping file with %d new mappings",
                len(output_data),
            )
            log.info("Total mappings in file: %d", len(existing_data))
            return output_file

        except RequestException as exc:
            log.error("Failed to download MITRE ATT&CK data: %s", exc)
            raise
        except json.JSONDecodeError as exc:
            log.error("Failed to parse MITRE ATT&CK JSON data: %s", exc)
            raise
        except Exception as exc:
            log.error("Unexpected error downloading MITRE TTPs: %s", exc)
            raise

    def load_ttp_mapping(self) -> Dict[str, str]:
        """Load the TTP mapping from the local file."""
        output_file = self._mapping_path()
        if not os.path.exists(output_file):
            log.warning("MITRE TTP mapping file does not exist")
            return {}

        try:
            with open(output_file, "r", encoding="utf-8") as handle:
                mapping = json.load(handle)
            log.info("Loaded %d TTP mappings from file", len(mapping))
            return mapping
        except (json.JSONDecodeError, OSError) as exc:
            log.error("Failed to load TTP mapping file: %s", exc)
            return {}
