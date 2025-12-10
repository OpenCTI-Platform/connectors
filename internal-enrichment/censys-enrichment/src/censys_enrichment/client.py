from censys_platform import SDK, Host


class Client:
    def __init__(self, organisation_id: str, token: str):
        self.organisation_id = organisation_id
        self.token = token

    def fetch_ip(self, ip: str) -> Host:
        """Fetch host data for a given IP address from Censys.
        Args:
            ip (str): The IP address to fetch data for.
        Returns:
            Host: The host data retrieved from Censys.
        Raises:
            ValueError: If no data is found for the given IP address.
        """
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            res = sdk.global_data.get_host(host_id=ip)
            if host_asset := res.result.result:
                return host_asset.resource
            raise ValueError(f"No data found for IP {ip}")
