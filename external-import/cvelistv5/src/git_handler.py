import git
import os
from datetime import datetime

class GitHandler:
    def __init__(self, repo_url, local_path):
        self.repo_url = repo_url
        self.local_path = local_path
        self.repo = self._init_repo()
        self.last_run_time = None

    def _init_repo(self):
        if not os.path.exists(self.local_path):
            return git.Repo.clone_from(self.repo_url, self.local_path)
        return git.Repo(self.local_path)

    def pull_updates(self):
        self.repo.remotes.origin.pull()

    def get_updated_files(self, start_year):
        if self.last_run_time is None:
            # First run, get all files from start_year
            return self._get_all_files_from_year(start_year)
        else:
            # Subsequent runs, get only files updated since last run
            return self._get_files_since_last_run()

    def _get_all_files_from_year(self, start_year):
        all_files = []
        cves_path = os.path.join(self.local_path, 'cves')

        # Iterate over all directories in the 'cves' path
        for folder_name in os.listdir(cves_path):
            if folder_name.isdigit() and int(folder_name) >= start_year:  # Check if folder name is a year and >= start_year
                folder_path = os.path.join(cves_path, folder_name)
                for root, _, files in os.walk(folder_path):  # Walk through the files in the directory
                    for file in files:
                        if file.endswith('.json'):  # Only process JSON files
                            all_files.append(os.path.join(root, file))
    
        self.update_last_run_time()
        return all_files

    def _get_files_since_last_run(self):
        commits = list(self.repo.iter_commits(f'main', since=self.last_run_time))
        updated_files = set()
        for commit in commits:
            updated_files.update(commit.stats.files.keys())
            
        self.update_last_run_time()
        return [os.path.join(self.local_path, f) for f in updated_files if f.startswith('cves/') and f.endswith('.json') and not f.endswith('delta.json')]

    def update_last_run_time(self):
        self.last_run_time = datetime.now()
