import os
import time
import json
import logging
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import stix2
from pycti import OpenCTIConnectorHelper, get_config_variable


class OSSFMaliciousPackagesConnector:
    def __init__(self):

        # Load config from file + env
        config = self._load_config()
        self.helper = OpenCTIConnectorHelper(config)

        # Connector-specific config
        self.github_repo_url = get_config_variable(
            "OSSF_GITHUB_REPO_URL", ["ossf", "github_repo_url"], config
        )
        self.github_branch = get_config_variable(
            "OSSF_GITHUB_BRANCH", ["ossf", "branch"], config, default="main"
        )
        self.local_repo_path = get_config_variable(
            "OSSF_LOCAL_REPO_PATH",
            ["ossf", "local_repo_path"],
            config,
            default="/opt/ossf-malicous-packages-repo",
        )
        self.run_interval = int(
            get_config_variable(
                "OSSF_RUN_INTERVAL_SECONDS",
                ["ossf", "run_interval_seconds"],
                config,
                default=86400,
            )
        )
        self.default_score = int(
            get_config_variable(
                "OSSF_DEFAULT_SCORE", ["ossf", "default_score"], config, default=80
            )
        )
        self.source_name = get_config_variable(
            "OSSF_SOURCE_NAME",
            ["ossf", "source_name"],
            config,
            default="ossf/malicious-packages",
        )

        self.helper.log_info("OSSF Malicious Packages connector initialized")

    @staticmethod
    def _load_config() -> Dict[str, Any]:
        """
        Load connector config from config.yml placed next to this file.
        """
        import yaml

        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, "config.yml")
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    # -------------------------------------------------------------------------
    # Git / repo utilities
    # -------------------------------------------------------------------------
    def _init_or_update_repo(self) -> None:
        """Clone or update the local ossf/malicious-packages repo."""
        if not os.path.isdir(self.local_repo_path):
            self.helper.log_info(
                f"Cloning {self.github_repo_url} into {self.local_repo_path}"
            )
            subprocess.check_call(
                [
                    "git",
                    "clone",
                    "--branch",
                    self.github_branch,
                    self.github_repo_url,
                    self.local_repo_path,
                ]
            )
        else:
            self.helper.log_info(f"Updating repo in {self.local_repo_path}")
            subprocess.check_call(
                ["git", "-C", self.local_repo_path, "fetch", "origin"]
            )
            subprocess.check_call(
                ["git", "-C", self.local_repo_path, "checkout", self.github_branch]
            )
            subprocess.check_call(
                ["git", "-C", self.local_repo_path, "pull", "origin", self.github_branch]
            )

    def _get_current_head(self) -> str:
        result = subprocess.check_output(
            ["git", "-C", self.local_repo_path, "rev-parse", "HEAD"]
        )
        return result.decode().strip()

    def _get_changed_files(
            self, old_commit: Optional[str], new_commit: str
    ) -> List[str]:
        """
        Return list of JSON files under osv/malicious/** that changed
        between old_commit and new_commit. If old_commit is None, return all.
        """
        if old_commit is None:
            malicious_dir = os.path.join(self.local_repo_path, "osv", "malicious")
            changed_files = []
            for root, _, files in os.walk(malicious_dir):
                for f in files:
                    if f.endswith(".json"):
                        changed_files.append(os.path.join(root, f))
            return changed_files

        diff_cmd = [
            "git",
            "-C",
            self.local_repo_path,
            "diff",
            "--name-only",
            f"{old_commit}..{new_commit}",
            "--",
            "osv/malicious",
        ]
        output = subprocess.check_output(diff_cmd).decode().splitlines()
        changed_files = [
            os.path.join(self.local_repo_path, p)
            for p in output
            if p.endswith(".json")
        ]
        return changed_files

    def _build_github_blob_url(self, file_path: str, commit: str) -> str:
        """
        Build a GitHub blob URL for a local file at a given commit.
        Example:
          https://github.com/ossf/malicious-packages/blob/<commit>/osv/malicious/...
        """
        rel_path = os.path.relpath(file_path, self.local_repo_path).replace("\\", "/")
        base = self.github_repo_url.replace(".git", "")
        return f"{base}/blob/{commit}/{rel_path}"

    # -------------------------------------------------------------------------
    # OSV parsing and hash extraction
    # -------------------------------------------------------------------------
    def _parse_osv_json(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Parse a single OSV JSON file into a simplified structure."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            self.helper.log_error(f"Error reading OSV JSON {file_path}: {e}")
            return None

        osv_id = data.get("id")
        summary = data.get("summary")
        affected = data.get("affected", [])
        if not affected:
            self.helper.log_info(f"No 'affected' section in {file_path}, skipping")
            return None

        pkg_info = affected[0].get("package", {})
        ecosystem = pkg_info.get("ecosystem", "unknown")
        name = pkg_info.get("name", "unknown")

        hashes = self._extract_hashes_from_osv(data)
        if not hashes:
            self.helper.log_info(f"No hashes found in {file_path}, skipping")
            return None

        return {
            "osv_id": osv_id,
            "summary": summary,
            "ecosystem": ecosystem,
            "package": name,
            "hashes": hashes,  # dict algo -> list[str]
        }

    def _extract_hashes_from_osv(self, osv_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract hashes from OSV entry in ossf/malicious-packages format.
        We look into:
          database_specific.malicious-packages-origins[].sha256
        Returns:
          {
            "SHA256": ["hash1", "hash2", ...]
          }
        """
        hashes: Dict[str, List[str]] = {}
        db_specific = osv_data.get("database_specific") or {}
        origins = db_specific.get("malicious-packages-origins") or []

        # If origins is not a list, skip
        if not isinstance(origins, list):
            return hashes

        for origin in origins:
            if not isinstance(origin, dict):
                continue
            sha256 = origin.get("sha256")
            if sha256:
                hashes.setdefault("SHA256", []).append(sha256)

        # Deduplicate while preserving order
        for algo, values in list(hashes.items()):
            seen = set()
            unique = []
            for v in values:
                if v not in seen:
                    seen.add(v)
                    unique.append(v)
            hashes[algo] = unique

        return hashes            

    # -------------------------------------------------------------------------
    # STIX creation
    # -------------------------------------------------------------------------
    def _create_objects_for_entry(
            self, parsed: Dict[str, Any], github_url: str
    ) -> List:
        """
        For a parsed OSV entry, create:
          - One File observable per hash
          - One Indicator per File
          - One 'based-on' relationship per Indicator→File
        """
        objects: List[stix2.DomainObject] = []

        ecosystem = parsed["ecosystem"]
        package = parsed["package"]
        summary = parsed.get("summary") or f"Malicious package {ecosystem}/{package}"
        name = f"{ecosystem}/{package}"
        score = self.default_score

        # Shared external reference (File + Indicator)
        external_ref = stix2.ExternalReference(
            source_name=self.source_name,
            url=github_url,
            external_id=parsed.get("osv_id"),
        )

        # For each algorithm and each value, create separate File + Indicator
        for algo, values in parsed["hashes"].items():
            for hash_value in values:
                # --- File observable ---
                file_kwargs = {
                    "type": "file",
                    "name": name,
                    "hashes": {algo: hash_value},
                    "custom_properties": {
                        "x_opencti_description": summary,
                        "x_opencti_score": score,
                        # OpenCTI allows external_references via custom_properties on SCOs
                        "external_references": [external_ref],
                    },
                }
                file_stix = stix2.File(**file_kwargs)
                objects.append(file_stix)

                # --- Indicator ---
                pattern = f"[file:hashes.'{algo}' = '{hash_value}']"
                now = datetime.now(timezone.utc)
                indicator = stix2.Indicator(
                    name=name,
                    description=summary,
                    pattern_type="stix",
                    pattern=pattern,
                    valid_from=now,
                    created=now,
                    custom_properties={
                        "x_opencti_main_observable_type": "File",
                        "x_opencti_score": score,
                        "external_references": [external_ref],
                    },
                )
                objects.append(indicator)

                # --- based-on relationship: Indicator → File ---
                rel = stix2.Relationship(
                    relationship_type="based-on",
                    source_ref=indicator.id,
                    target_ref=file_stix.id,
                )
                objects.append(rel)

        return objects

    # -------------------------------------------------------------------------
    # Main processing logic
    # -------------------------------------------------------------------------
    def _process_once(self) -> None:
        self.helper.log_info("Starting OSSF Malicious Packages run")

        # 1. Ensure repository is up-to-date
        self._init_or_update_repo()
        current_head = self._get_current_head()

        # 2. Get connector state
        state = self.helper.get_state() or {}
        last_commit = state.get("last_commit")
        self.helper.log_info(
            f"Last commit in state: {last_commit}, current HEAD: {current_head}"
        )

        # 3. Determine which JSON files to process
        changed_files = self._get_changed_files(last_commit, current_head)
        self.helper.log_info(
            f"Found {len(changed_files)} OSV JSON files to process this run"
        )

        all_objects: List = []

        # 4. Parse each changed file and create STIX objects
        for file_path in changed_files:
            parsed = self._parse_osv_json(file_path)
            if not parsed:
                continue
            github_url = self._build_github_blob_url(file_path, current_head)
            objs = self._create_objects_for_entry(parsed, github_url)
            if not objs:
                continue
            all_objects.extend(objs)

        if not all_objects:
            self.helper.log_info("No new objects to send this run")
        else:
            # 5. Bundle and send to OpenCTI
            bundle = self.helper.stix2_create_bundle(all_objects)
            self.helper.send_stix2_bundle(bundle)
            self.helper.log_info(
                f"Sent bundle with {len(all_objects)} STIX objects to OpenCTI"
            )

        # 6. Update connector state
        new_state = {
            "last_commit": current_head,
            "last_run": datetime.now(timezone.utc).isoformat(),
        }
        self.helper.set_state(new_state)
        self.helper.log_info(f"State updated: {new_state}")

    def run(self) -> None:
        self.helper.log_info(
            "Starting OSSF Malicious Packages connector main loop"
        )
        while True:
            try:
                self._process_once()
            except Exception as e:
                self.helper.log_error(f"Error during processing: {e}")
            self.helper.log_info(
                f"Sleeping for {self.run_interval} seconds before next run"
            )
            time.sleep(self.run_interval)


if __name__ == "__main__":
    try:
        connector = OSSFMaliciousPackagesConnector()
        connector.run()
    except Exception as e:
        logging.exception(e)
        raise
