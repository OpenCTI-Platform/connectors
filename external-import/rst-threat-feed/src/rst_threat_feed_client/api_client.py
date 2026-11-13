"""RST Cloud Threat Feed HTTP client."""

import zlib
from typing import Any, Dict, Optional

import requests


class ThreatFeedClient:
    """Download compressed IOC feeds from the RST Cloud Threat Feed API."""

    def __init__(self, conf: Dict[str, Any]) -> None:
        self.api_url = str(conf.get("baseurl", "https://api.rstcloud.net/v1")).rstrip(
            "/"
        )
        self.api_key = str(conf.get("apikey", "REPLACEME"))
        self.timeout = (
            int(conf.get("contimeout", 30)),
            int(conf.get("readtimeout", 120)),
        )
        self.retry = int(conf.get("retry", 2))
        self.verify = bool(conf.get("ssl_verify", True))
        self.proxy = str(conf.get("proxy", "") or "").strip()
        self.time_range = str(conf.get("latest", "day"))

        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": "opencti_rst_threat_feed",
                "Accept": "*/*",
                "X-Api-Key": self.api_key,
            }
        )
        if self.proxy:
            self._session.proxies = {"http": self.proxy, "https": self.proxy}

    def get_feed(
        self, ioctype: str, path: str = "", filetype: str = "json"
    ) -> Dict[str, Any]:
        mapping = {
            "day": "latest",
            "1h": "1h_latest",
            "4h": "4h_latest",
            "12h": "12h_latest",
        }
        fdate = self.time_range
        if fdate not in mapping:
            return {
                "status": "error",
                "message": f"Unsupported latest window: {fdate}",
            }
        if not path:
            path = f"threatfeed_{ioctype}_{mapping[fdate]}.{filetype}.gz"
        apiurl = f"{self.api_url}/{ioctype}?type={filetype}&date={mapping[fdate]}"
        last_error: Optional[Exception] = None
        attempts = max(1, int(self.retry) + 1)

        for _ in range(attempts):
            try:
                response = self._session.get(
                    apiurl,
                    timeout=self.timeout,
                    verify=self.verify,
                )
                if response.status_code == 200:
                    data = zlib.decompress(response.content, 16 + zlib.MAX_WBITS)
                    with open(path, "wb") as handle:
                        handle.write(data)
                    return {"status": "ok", "message": path}
                try:
                    return response.json()
                except Exception:
                    return {
                        "status": "error",
                        "message": (
                            f"HTTP {response.status_code}: {response.text[:200]}"
                        ),
                    }
            except Exception as exc:
                last_error = exc

        return {
            "status": "error",
            "message": str(last_error) if last_error else "Unknown download error",
        }
