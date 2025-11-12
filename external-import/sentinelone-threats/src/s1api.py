import io
import json
import urllib.parse
import zipfile
from urllib.request import Request, urlopen


class SentinelOneApi:
    """
    Simple wrapper for SentinelOne API v2.1
    """

    def __init__(self, api_url, api_token):
        """
        api_url: str representing the endpoint to call the SentinelOne API, e.g. https://xxxxxxx.sentinelone.net
        api_token: str representing the API token
        """
        self._api_url = api_url
        # TODO the api token automatically re-generates after 6 months
        self._headers = {"Authorization": f"ApiToken {api_token}"}

    def get_threats(self, created_at_gt=None):
        """
        Get threats, see {api_url}/api-doc/api-details?category=threats&api=get-threats

        created_at_gt: a str to filter for created at greater than. Example: "2018-02-27T04:49:26.257525Z".

        returns: a generator that yeilds each json dict response
        """

        url = f"{self._api_url}/web/api/v2.1/threats"
        params = {}
        if created_at_gt:
            params["createdAt__gt"] = created_at_gt

        last_cursor = None
        while True:
            try:
                if last_cursor:
                    params.pop("createdAt__gt", None)
                    params["cursor"] = last_cursor

                query_string = urllib.parse.urlencode(params)
                threats_url = f"{url}?{query_string}"

                req = Request(threats_url, headers=self._headers)
                resp = urlopen(req).read().decode()
                threats_list = json.loads(resp)
                last_cursor = threats_list.get("pagination").get("nextCursor", None)
                if not last_cursor or not threats_list.get("data"):
                    break

                yield threats_list

            except Exception as e:
                print(f"Failed to get threats, exception: {e}")

    def download_threat(self, threat_id):
        """
        Download a threat file from the cloud.
        See {api_url}/api-doc/api-details?category=threats&api=download-from-cloud

        threat_id: a str representing the threat id,
                   acquired by calling get_threats() and passing the "id" key's value
        returns: a bytes object with the file contents
        """
        url = f"{self._api_url}/web/api/v2.1/threats/{threat_id}/download-from-cloud"
        file_contents = b""

        try:
            req = Request(url, headers=self._headers)
            resp = urlopen(req).read()
            resp_dict = json.loads(resp)
            download_url = resp_dict["data"]["downloadUrl"]
            req = Request(download_url)

            # Process password protected zip archive
            zip_contents = urlopen(req).read()
            zip_object = io.BytesIO(zip_contents)
            zf = zipfile.ZipFile(zip_object)
            zf.setpassword(b"S1BinaryVault")
            for filename in zf.namelist():
                # The threat file is stored in the zip at
                # C/ProgramData/Sentinel/AFUCache/<threat>
                if "C/ProgramData/Sentinel/AFUCache/" in filename:
                    with zf.open(filename) as f:
                        file_contents = f.read()
                        break

        except Exception as e:
            print(f"Failed to download threat, exception: {e}")

        return file_contents
