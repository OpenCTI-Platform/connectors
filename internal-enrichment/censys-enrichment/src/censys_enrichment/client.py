from censys_platform import SDK, Host


class Client:
    def __init__(self, organisation_id: str, token: str):
        self.organisation_id = organisation_id
        self.token = token

    def fetch_ip(self, ip: str) -> Host:
        with SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
        ) as sdk:
            res = sdk.global_data.get_host(host_id=ip)
            if host_asset := res.result.result:
                return host_asset.resource
            raise ValueError(f"No data found for IP {ip}")
