import logging
import requests
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class WhoisFreaksClient:
    """
    Client for interacting with WhoisFreaks REST APIs.
    Docs: https://whoisfreaks.com/documentation
    """

    BASE_URL = "https://api.whoisfreaks.com"

    def __init__(self, api_key: str, timeout: Optional[int] = 30):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "OpenCTI-WhoisFreaks-Connector/1.0",
                "Accept": "application/json",
            }
        )

    def _post(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        body: Optional[dict] = None,
        timeout: int = 30,
    ) -> Optional[Dict[str, Any]]:
        url = f"{self.BASE_URL}{endpoint}"
        if params is None:
            params = {}
        params["apiKey"] = self.api_key

        try:
            response = self.session.post(url, params=params, json=body, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(
                    f"[WhoisFreaks API] POST {url} failed HTTP {response.status_code}: {response.text}"
                )
                return None
        except requests.exceptions.Timeout:
            logger.error(f"[WhoisFreaks API] Timeout reaching {url}.")
            return None
        except requests.RequestException as e:
            logger.error(f"[WhoisFreaks API] Error during POST {url}: {e}")
            return None

    def _get(
        self, endpoint: str, params: Optional[dict] = None, timeout: int = 30
    ) -> Optional[Dict[str, Any]]:
        url = f"{self.BASE_URL}{endpoint}"
        if params is None:
            params = {}
        params["apiKey"] = self.api_key

        try:
            response = self.session.get(url, params=params, timeout=timeout)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.info(f"[WhoisFreaks API] No record found at {endpoint}")
                return None
            elif response.status_code == 401:
                logger.error(
                    "[WhoisFreaks API] Unauthorized - Check WHOISFREAKS_API_KEY."
                )
                return None
            elif response.status_code == 429:
                logger.error(
                    "[WhoisFreaks API] Rate limit reached or insufficient credits."
                )
                return None
            else:
                logger.error(
                    f"[WhoisFreaks API] GET {url} failed HTTP {response.status_code}: {response.text}"
                )
                return None
        except requests.exceptions.Timeout:
            logger.error(f"[WhoisFreaks API] Timeout reaching {url}.")
            return None
        except requests.RequestException as e:
            logger.error(f"[WhoisFreaks API] Error during GET {url}: {e}")
            return None

    # --- API ENDPOINT WRAPPERS ---
    def live_whois_lookup(
        self, domain: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v2.0/whois/live", params={"format": format, "domainName": domain}
        )

    def historical_whois_lookup(
        self, domain: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v2.0/whois",
            params={"format": format, "domainName": domain, "whois": "historical"},
        )

    def reverse_whois_lookup(
        self, keyword: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v1.0/whois",
            params={"format": format, "keyword": keyword, "whois": "reverse"},
        )

    def bulk_whois_lookup(
        self, domains: list[str], format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._post(
            "/v2.0/bulkwhois/live",
            params={"format": format},
            body={"domainNames": domains},
        )

    def live_dns_lookup(
        self, domain: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v2.0/dns/live",
            params={"format": format, "domainName": domain, "type": "all"},
        )

    def historical_dns_lookup(
        self, domain: str, format: Optional[str] = "json", page: Optional[int] = 1
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v2.0/dns/historical",
            params={
                "format": format,
                "domainName": domain,
                "type": "all",
                "page": page,
            },
        )

    def reverse_dns_lookup(
        self, ip_address: str, format: Optional[str] = "json", page: Optional[int] = 1
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v2.0/dns/reverse",
            params={
                "format": format,
                "value": ip_address,
                "page": page,
                "type": "a",
                "exact": True,
            },
        )

    def bulk_dns_lookup(
        self, domains: list[str], ipAddresses: list[str], format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._post(
            "/v2.0/dns/bulk/live",
            params={"format": format, "type": "all"},
            body={"domainNames": domains, "ipAddresses": ipAddresses},
        )

    def domain_availability_lookup(
        self, domain: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v1.0/domain/availability",
            params={"format": format, "domainName": domain, "sug": False},
        )

    def bulk_domain_availability_lookup(
        self, domains: list[str], format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._post(
            "/v1.0/domain/availability",
            params={"format": format},
            body={"domainNames": domains},
        )

    def typosquatting_lookup(self, keyword: str) -> Optional[Dict[str, Any]]:
        return self._get("/v3.0/domain/typos", params={"keyword": keyword})

    def ssl_lookup(
        self, domain: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v1.0/ssl/live",
            params={
                "format": format,
                "domainName": domain,
                "chain": True,
                "sslRaw": False,
            },
        )

    def ip_geolocation_lookup(
        self, ip_address: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v1.0/geolocation", params={"format": format, "ip": ip_address}
        )

    def bulk_ip_geolocation_lookup(
        self, ip_addresses: list[str]
    ) -> Optional[Dict[str, Any]]:
        return self._post("/v1.0/geolocation", body={"ips": ip_addresses})

    def subdomains_lookup(
        self, domain: str, format: Optional[str] = "json", page: Optional[int] = 1
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v1.0/subdomains",
            params={"format": format, "domain": domain, "page": page},
        )

    def ip_reputation_lookup(self, ip_address: str) -> Optional[Dict[str, Any]]:
        return self._get("/v1.0/security", params={"ip": ip_address})

    def bulk_ip_reputation_lookup(
        self, ip_addresses: list[str]
    ) -> Optional[Dict[str, Any]]:
        return self._post("/v1.0/security", body={"ips": ip_addresses})

    def asn_whois_lookup(
        self, asn: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get("/v2.0/asn-whois", params={"asn": asn, "format": format})

    def ip_whois_lookup(
        self, ip_address: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get("/v1.0/ip-whois", params={"ip": ip_address, "format": format})

    def domain_reputation_lookup(
        self, domain: str, format: Optional[str] = "json"
    ) -> Optional[Dict[str, Any]]:
        return self._get(
            "/v1.0/domain-reputation", params={"domainName": domain, "format": format}
        )

    def account_usage(self) -> Optional[Dict[str, Any]]:
        return self._get("/v1.0/whoisapi/usage")

    def rotate_api_key(self) -> Optional[Dict[str, Any]]:
        return self._post("/v1.0/api-key/rotate")
