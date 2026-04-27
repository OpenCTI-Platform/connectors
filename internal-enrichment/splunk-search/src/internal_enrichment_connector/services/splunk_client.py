class SplunkClient:
    def __init__(self, url, token, verify_ssl=True):
        self.url = url
        self.token = token
        self.verify_ssl = verify_ssl

    def health_check(self):
        """Perform a simple Splunk search to verify connectivity and token."""
        import requests
        headers = {'Authorization': f'Splunk {self.token}'}
        params = {'search': '_index=_internal limit 1', 'count': 1}
        try:
            resp = requests.get(f"{self.url}/services/search/jobs", headers=headers, params=params, verify=self.verify_ssl, timeout=10)
            resp.raise_for_status()
            return resp.json().get('entry', [])
        except Exception as e:
            raise RuntimeError(f"Splunk health check failed: {e}")

    def send_event(self, event):
        """Send a single event to Splunk via HTTP Event Collector."""
        import requests
        import json
        hec_url = f"{self.url}/services/collector"
        headers = {'Authorization': f'Splunk {self.token}'}
        payload = json.dumps({"event": event})
        try:
            resp = requests.post(hec_url, headers=headers, data=payload, verify=self.verify_ssl, timeout=10)
            resp.raise_for_status()
        except Exception as e:
            raise RuntimeError(f"Failed to send event to Splunk: {e}")
