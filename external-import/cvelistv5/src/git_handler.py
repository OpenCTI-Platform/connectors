"""Git interactions for the cvelistV5 connector.

The connector consumes CVE records straight from the CVEProject/cvelistV5
GitHub repository. This module is responsible for keeping a local clone in
sync and listing the JSON files that need to be (re)processed for a given
connector run.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Iterable

import git

CVES_DIRECTORY = "cves"
# Files that live inside the repository but should never be processed as CVE
# records. They are aggregate artifacts produced by upstream tooling.
EXCLUDED_FILE_SUFFIXES = ("delta.json", "deltaLog.json")


class GitHandler:
    """Wrapper around :mod:`git` used to keep a local clone in sync."""

    def __init__(
        self,
        repo_url: str,
        local_path: str,
        branch: str = "main",
        logger: logging.Logger | None = None,
    ) -> None:
        self.repo_url = repo_url
        self.local_path = local_path
        self.branch = branch
        self.logger = logger or logging.getLogger(__name__)
        self.repo = self._init_repo()
        self.last_run_time: datetime | None = None

    def _init_repo(self) -> git.Repo:
        """Return a :class:`git.Repo` rooted at ``self.local_path``.

        Clones the upstream repository when the directory is empty, otherwise
        opens the existing clone.
        """
        if not os.path.exists(self.local_path) or not os.listdir(self.local_path):
            self.logger.info(
                "Cloning upstream repository.",
                {"repo_url": self.repo_url, "local_path": self.local_path},
            )
            os.makedirs(self.local_path, exist_ok=True)
            return git.Repo.clone_from(
                self.repo_url,
                self.local_path,
                branch=self.branch,
                single_branch=True,
            )
        return git.Repo(self.local_path)

    def pull_updates(self) -> None:
        """Hard-reset the clone to the latest remote branch tip.

        Using ``fetch`` + ``reset --hard`` instead of ``pull`` makes the
        operation idempotent and avoids merge conflicts if the working tree
        is somehow modified between runs.
        """
        origin = self.repo.remotes.origin
        origin.fetch(self.branch, prune=True)
        remote_ref = f"origin/{self.branch}"
        self.repo.git.reset("--hard", remote_ref)

    def get_updated_files(self, start_year: int) -> list[str]:
        """Return the list of CVE JSON files to (re)process for this run."""
        if self.last_run_time is None:
            files = self._get_all_files_from_year(start_year)
        else:
            files = list(self._get_files_since(self.last_run_time, start_year))
        return files

    def update_last_run_time(self, run_time: datetime | None = None) -> None:
        if run_time is None:
            run_time = datetime.now(timezone.utc)
        elif run_time.tzinfo is None:
            run_time = run_time.replace(tzinfo=timezone.utc)
        self.last_run_time = run_time

    def _get_all_files_from_year(self, start_year: int) -> list[str]:
        all_files: list[str] = []
        cves_path = os.path.join(self.local_path, CVES_DIRECTORY)
        if not os.path.isdir(cves_path):
            self.logger.warning(
                "Expected CVE directory is missing in the clone.",
                {"path": cves_path},
            )
            return all_files

        for folder_name in sorted(os.listdir(cves_path)):
            if not folder_name.isdigit():
                continue
            if int(folder_name) < start_year:
                continue
            folder_path = os.path.join(cves_path, folder_name)
            for root, _, files in os.walk(folder_path):
                for file_name in files:
                    if not file_name.endswith(".json"):
                        continue
                    if file_name.endswith(EXCLUDED_FILE_SUFFIXES):
                        continue
                    all_files.append(os.path.join(root, file_name))
        return all_files

    def _get_files_since(self, since: datetime, start_year: int) -> Iterable[str]:
        commits = list(self.repo.iter_commits(self.branch, since=since.isoformat()))
        updated_files: set[str] = set()
        for commit in commits:
            updated_files.update(commit.stats.files.keys())

        prefix = f"{CVES_DIRECTORY}/"
        for relative_path in updated_files:
            if not relative_path.startswith(prefix):
                continue
            if not relative_path.endswith(".json"):
                continue
            if relative_path.endswith(EXCLUDED_FILE_SUFFIXES):
                continue
            # Records are organised under ``cves/<year>/...``. Skip records
            # older than the configured horizon.
            parts = relative_path.split("/")
            if len(parts) >= 2 and parts[1].isdigit():
                if int(parts[1]) < start_year:
                    continue
            yield os.path.join(self.local_path, relative_path)
