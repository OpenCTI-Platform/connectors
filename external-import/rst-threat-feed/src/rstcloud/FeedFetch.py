import zlib

import requests


class Downloader:
    def __init__(self, conf):
        # connection
        self.api_url = str(conf.get("baseurl", "https://api.rstcloud.net/v1/"))
        self.api_key = str(conf.get("apikey", "REPLACEME"))
        self.timeout = (
            int(conf.get("contimeout", 30)),
            int(conf.get("readtimeout", 60)),
        )
        self.retry = int(conf.get("retry", 5))
        self.verify = bool(conf.get("ssl_verify", True))
        self.proxy = str(conf.get("proxy", ""))
        self.time_range = str(conf.get("latest", "latest"))

    def get_feed(self, ioctype: str, path="", filetype="json"):
        fdate = self.time_range
        mapping = {
            "day": "latest",
            "1h": "1h_latest",
            "4h": "4h_latest",
            "12h": "12h_latest",
        }
        if not path:
            path = f"threatfeed_{ioctype}_{mapping[fdate]}.{filetype}.gz"
        apiurl = f"{self.api_url}/{ioctype}?type={filetype}&date={mapping[fdate]}"
        headers = {
            "User-Agent": "opencti_rst_threat_feed",
            "Accept": "*/*",
            "X-Api-Key": self.api_key,
        }
        proxies = {"https": self.proxy}
        r = requests.get(apiurl, headers=headers, proxies=proxies, timeout=self.timeout)
        try:
            if r.status_code == 200:
                data = zlib.decompress(r.content, 16 + zlib.MAX_WBITS)
                with open(path, "wb") as f:
                    f.write(data)
                return {"status": "ok", "message": path}
            else:
                return r.json()
        except Exception as ex:
            return {"status": "error", "message": str(ex)}
