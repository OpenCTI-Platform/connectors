import io

import requests


class IntezerApi:
    """
    A simple wrapper for the Intezer API v2.
    """

    def __init__(self, api_key):
        self.base_url = "https://analyze.intezer.com/api/v2-0"

        access_token = self._get_access_token(api_key)
        self._session = requests.session()
        self._session.headers["Authorization"] = f"Bearer {access_token}"

    def _get_access_token(self, api_key):
        response = requests.post(
            f"{self.base_url}/get-access-token", json={"api_key": api_key}
        )
        response.raise_for_status()
        return response.json()["result"]

    def upload_file(self, file_name, file_contents):
        """
        Upload a file for analysis.

        file_name: a str representing the name of the file
        file_contents: a bytes object containing the contents of the file

        returns: a str containing the URL for querying the analysis' status
        """

        file_obj = io.BytesIO(file_contents)
        files = {"file": ("file_name", file_obj)}
        response = self._session.post(f"{self.base_url}/analyze", files=files)
        response.raise_for_status()
        return response.json()["result_url"]

    def get_analysis_report(self, result_url):
        """
        Get an analysis' report. For use after obtaining result url by upload_file method.

        returns: a dict in the form:
                {
                    'result': {'analysis_id': 'f010f718-8cea-4f00-9113-a3f6e346a164',
                            'analysis_time': 'Tue, 13 Nov 2018 09:10:42 GMT',
                            'analysis_url': 'https://analyze.intezer.com/analyses/f010f718-8cea-4f00-9113-a3f6e346a164',
                            'family_name': 'Cedar',
                            'is_private': True,
                            'sha256': 'e5b68ab68b12c3eaff612ada09eb2d4c403f923cdec8a5c8fe253c6773208baf',
                            'sub_verdict': 'malicious',
                            'verdict': 'malicious'
                    },
                    'result_url': '/analyses/f010f718-8cea-4f00-9113-a3f6e346a164',
                    'status': 'succeeded'
                }
        """

        response = self._session.get(f"{self.base_url}{result_url}")
        response.raise_for_status()
        report_dict = response.json()
        return report_dict
