import json
import ssl
import sys
import time
import urllib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pycti import AttackPattern, Identity, OpenCTIConnectorHelper
from src import ConfigLoader
from stix2.canonicalization.Canonicalize import canonicalize

FT3_TACTICS_URL = (
    "https://raw.githubusercontent.com/stripe/ft3/refs/heads/master/FT3_Tactics.json"
)
FT3_TECHNIQUES_URL = (
    "https://raw.githubusercontent.com/stripe/ft3/refs/heads/master/FT3_Techniques.json"
)


def time_from_unixtime(timestamp):
    if not timestamp:
        return None
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def get_unixtime_now():
    return int(time.time())


def days_to_seconds(days):
    return int(days) * 24 * 60 * 60


def generate_x_opencti_id(type_prefix: str, name: str, namespace: str = "ft3") -> str:
    """Generate ID for x-opencti types using canonical method."""
    data = {"name": name.lower().strip()}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return f"{type_prefix}--{id}"


def generate_x_mitre_tactic_id(name: str) -> str:
    """Generate ID for x-mitre-tactic using canonical method."""
    data = {"name": name.lower().strip()}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return f"x-mitre-tactic--{id}"


class FT3:
    """FT3 connector."""

    def __init__(self):
        # Load configuration file and connection helper
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(config=self.config.model_dump_pycti())

        # Configuration
        self.ft3_interval = self.config.ft3.interval
        self.ft3_tactics_url = self.config.ft3.tactics_url
        self.ft3_techniques_url = self.config.ft3.techniques_url
        self.interval = days_to_seconds(self.ft3_interval)

        # Identity for Stripe as the creator
        self.stripe_identity = self._create_stripe_identity()
        # Kill chain definition for FT3
        self.ft3_kill_chain = self._create_ft3_kill_chain()

    def _create_stripe_identity(self) -> Dict:
        """Create the identity object for Stripe."""
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": Identity.generate_id("Stripe", "organization"),
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "name": "Stripe",
            "description": "Stripe - Creator of the FT3 (Fraud Tactics, Techniques, and Procedures) framework",
            "identity_class": "organization",
        }

    def _create_ft3_kill_chain(self) -> Dict:
        """Create the kill chain definition for FT3."""
        return {
            "type": "x-opencti-kill-chain",
            "spec_version": "2.1",
            "id": generate_x_opencti_id("kill-chain", "fraud-attack"),
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "name": "Fraud Attack",
            "description": "The FT3 framework kill chain for fraud attack patterns",
            "kill_chain_name": "fraud-attack",
            "created_by_ref": self.stripe_identity["id"],
        }

    def _convert_date(self, date_str: str) -> str:
        """Convert date from FT3 format to STIX 2.1 format."""
        try:
            # Handle formats like "01/30/2024" or "1/30/24"
            if "/" in date_str:
                parts = date_str.split("/")
                month = int(parts[0])
                day = int(parts[1])
                year = int(parts[2])
                if year < 100:
                    year += 2000
                return datetime(year, month, day).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except:
            pass
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def retrieve_data(self, url: str) -> Optional[List]:
        """
        Retrieve JSON data from the given url.

        Parameters
        ----------
        url : str
            Url to retrieve.

        Returns
        -------
        List
            A list with the JSON content or None in case of failure.
        """
        try:
            # Fetch json from GitHub
            response = urllib.request.urlopen(
                url,
                context=ssl.create_default_context(),
            )
            data = json.loads(response.read().decode("utf-8"))
            return data
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.log_error(f"Error retrieving url {url}: {urllib_error}")
            self.helper.metric.inc("client_error_count")
        return None

    def convert_tactics_to_stix(self, tactics_data: List[Dict]) -> List[Dict]:
        """Convert FT3 tactics to STIX 2.1 format."""
        stix_objects = []

        for tactic in tactics_data:
            # Create x-mitre-tactic object using proper ID generation
            tactic_name = tactic["name"]
            # Create shortname from tactic name (lowercase, replace spaces with hyphens)
            shortname = tactic_name.lower().replace(" ", "-").replace("&", "and")
            stix_tactic = {
                "type": "x-mitre-tactic",
                "spec_version": "2.1",
                "id": generate_x_mitre_tactic_id(tactic_name),
                "created": self._convert_date(tactic.get("created", "")),
                "modified": self._convert_date(tactic.get("last_modified", "")),
                "name": tactic_name,
                "description": tactic.get("description", ""),
                "x_mitre_shortname": shortname,
                "external_references": [
                    {"source_name": "FT3", "external_id": tactic["ID"]}
                ],
                "created_by_ref": self.stripe_identity["id"],
                "object_marking_refs": [
                    "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
                ],
            }

            if tactic.get("url") and tactic["url"]:
                stix_tactic["external_references"][0]["url"] = tactic["url"]

            stix_objects.append(stix_tactic)

        return stix_objects

    def convert_techniques_to_stix(
        self, techniques_data: List[Dict], tactics_map: Dict[str, str]
    ) -> List[Dict]:
        """Convert FT3 techniques to STIX 2.1 format."""
        stix_objects = []

        for technique in techniques_data:
            # Determine if this is a sub-technique
            is_subtechnique = technique.get("is_sub-technique", "").upper() == "TRUE"

            # Create attack-pattern object using proper ID generation
            # Use the FT3 ID as the external_id for consistent ID generation
            technique_name = technique["name"]
            technique_ft3_id = technique["id"]

            stix_technique = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": AttackPattern.generate_id(technique_name, technique_ft3_id),
                "created": self._convert_date(technique.get("created", "")),
                "modified": self._convert_date(technique.get("last_modified", "")),
                "name": technique_name,
                "description": technique.get("description", ""),
                "x_mitre_id": technique_ft3_id,
                "external_references": [
                    {"source_name": "FT3", "external_id": technique_ft3_id}
                ],
                "created_by_ref": self.stripe_identity["id"],
                "object_marking_refs": [
                    "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
                ],
            }

            # Add kill chain phases based on tactics
            if technique.get("tactics"):
                kill_chain_phases = []
                tactics_list = (
                    technique["tactics"].split(",")
                    if "," in technique["tactics"]
                    else [technique["tactics"]]
                )

                for tactic_name in tactics_list:
                    tactic_name = tactic_name.strip()
                    # Create phase name from tactic name (lowercase, replace spaces with hyphens)
                    phase_name = (
                        tactic_name.lower().replace(" ", "-").replace("&", "and")
                    )
                    kill_chain_phases.append(
                        {"kill_chain_name": "fraud-attack", "phase_name": phase_name}
                    )

                if kill_chain_phases:
                    stix_technique["kill_chain_phases"] = kill_chain_phases

            # Add detection information if available
            if technique.get("detection") and technique["detection"]:
                stix_technique["x_mitre_detection"] = technique["detection"]

            # Add sub-technique flag if needed
            if is_subtechnique:
                stix_technique["x_mitre_is_subtechnique"] = True

            stix_objects.append(stix_technique)

        return stix_objects

    def create_relationships(self, techniques_data: List[Dict]) -> List[Dict]:
        """Create relationships between techniques and sub-techniques."""
        relationships = []

        for technique in techniques_data:
            if technique.get(
                "is_sub-technique", ""
            ).upper() == "TRUE" and technique.get("sub-technique of"):
                parent_id = technique["sub-technique of"]
                # Find parent technique name
                parent_technique = next(
                    (t for t in techniques_data if t["id"] == parent_id), None
                )
                if parent_technique:
                    relationship_id = str(
                        uuid.uuid5(
                            uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"),
                            f"ft3.{technique['id']}.subtechnique-of.{parent_id}",
                        )
                    )

                    relationship = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": f"relationship--{relationship_id}",
                        "created": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S.%fZ"
                        ),
                        "modified": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S.%fZ"
                        ),
                        "relationship_type": "subtechnique-of",
                        "source_ref": AttackPattern.generate_id(
                            technique["name"], technique["id"]
                        ),
                        "target_ref": AttackPattern.generate_id(
                            parent_technique["name"], parent_id
                        ),
                        "created_by_ref": self.stripe_identity["id"],
                        "object_marking_refs": [
                            "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
                        ],
                    }
                    relationships.append(relationship)

        return relationships

    def process_data(self):
        unixtime_now = get_unixtime_now()
        time_now = time_from_unixtime(unixtime_now)

        current_state = self.helper.get_state()
        last_run = current_state.get("last_run", None) if current_state else None
        self.helper.log_debug(f"Connector last run: {time_from_unixtime(last_run)}")

        if last_run and self.interval > unixtime_now - last_run:
            self.helper.log_debug("Connector will not run this time.")
            return

        self.helper.log_info(f"Connector will run now {time_now}.")
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        friendly_name = f"FT3 Framework run @ {time_now}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        try:
            self.helper.log_info("Fetching FT3 tactics...")
            tactics_data = self.retrieve_data(self.ft3_tactics_url)

            if not tactics_data:
                self.helper.log_error("Failed to retrieve tactics data")
                return

            self.helper.log_info(f"Retrieved {len(tactics_data)} tactics")

            self.helper.log_info("Fetching FT3 techniques...")
            techniques_data = self.retrieve_data(self.ft3_techniques_url)

            if not techniques_data:
                self.helper.log_error("Failed to retrieve techniques data")
                return

            self.helper.log_info(f"Retrieved {len(techniques_data)} techniques")

            # Create a mapping of tactic IDs to names for reference
            tactics_map = {tactic["ID"]: tactic["name"] for tactic in tactics_data}

            # Convert to STIX 2.1
            stix_objects = []

            # Add identity and kill chain
            stix_objects.append(self.stripe_identity)
            stix_objects.append(self.ft3_kill_chain)

            # Convert tactics
            self.helper.log_info("Converting tactics to STIX 2.1...")
            stix_tactics = self.convert_tactics_to_stix(tactics_data)
            stix_objects.extend(stix_tactics)

            # Convert techniques
            self.helper.log_info("Converting techniques to STIX 2.1...")
            stix_techniques = self.convert_techniques_to_stix(
                techniques_data, tactics_map
            )
            stix_objects.extend(stix_techniques)

            # Create relationships
            self.helper.log_info("Creating relationships...")
            relationships = self.create_relationships(techniques_data)
            stix_objects.extend(relationships)

            # Create STIX bundle
            stix_bundle = {
                "type": "bundle",
                "id": "bundle--" + str(uuid.uuid4()),
                "objects": stix_objects,
            }

            # Send to OpenCTI
            self.helper.log_info(
                f"Sending {len(stix_objects)} STIX objects to OpenCTI..."
            )
            self.helper.send_stix2_bundle(
                json.dumps(stix_bundle),
                entities_types=self.helper.connect_scope,
                work_id=work_id,
            )
            self.helper.metric.inc("record_send", len(stix_objects))

            message = f"Connector successfully run, storing last_run as {time_now}"
            self.helper.log_info(message)
            self.helper.set_state({"last_run": unixtime_now})
            self.helper.api.work.to_processed(work_id, message)

        except Exception as e:
            self.helper.log_error(f"Error processing FT3 data: {str(e)}")
            self.helper.api.work.to_processed(work_id, str(e), True)
            raise

    def run(self):
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)

        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
            return

        while True:
            try:
                self.process_data()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                self.helper.metric.state("stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
            finally:
                self.helper.metric.state("idle")
                time.sleep(60)


if __name__ == "__main__":
    try:
        ft3Connector = FT3()
        ft3Connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
