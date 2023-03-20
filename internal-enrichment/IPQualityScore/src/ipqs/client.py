# -*- coding: utf-8 -*-
"""IPQS client module."""
from pycti import OpenCTIConnectorHelper
from requests import Response, session
from requests.exceptions import (ConnectTimeout, HTTPError, InvalidURL,
                                 ProxyError)


class IPQSClient:
    """IPQS client."""

    def __init__(
        self, helper: OpenCTIConnectorHelper, base_url: str, api_key: str
    ) -> None:
        """Initialize IPQS client."""
        self.helper = helper
        self.url = base_url
        self.headers = {"IPQS-KEY": api_key}
        self.session = session()
        self.ip_enrich_fields = {
            "zip_code": "Zip Code",
            "ISP": "ISP",
            "ASN": "ASN",
            "organization": "Organization",
            "is_crawler": "Is Crawler",
            "timezone": "Timezone",
            "mobile": "Mobile",
            "host": "Host",
            "proxy": "Proxy",
            "vpn": "VPN",
            "tor": "TOR",
            "active_vpn": "Active VPN",
            "active_tor": "Active TOR",
            "recent_abuse": "Recent Abuse",
            "bot_status": "Bot Status",
            "connection_type": "Connection Type",
            "abuse_velocity": "Abuse Velocity",
            "country_code": "Country Code",
            "region": "Region",
            "city": "City",
            "latitude": "Latitude",
            "longitude": "Longitude",
        }
        self.url_enrich_fields = {
            "unsafe": "Unsafe",
            "server": "Server",
            "domain_rank": "Domain Rank",
            "dns_valid": "DNS Valid",
            "parking": "Parking",
            "spamming": "Spamming",
            "malware": "Malware",
            "phishing": "Phishing",
            "suspicious": "Suspicious",
            "adult": "Adult",
            "category": "Category",
            "domain_age": "Domain Age",
            "domain": "IPQS: Domain",
            "ip_address": "IPQS: IP Address",
        }
        self.email_enrich_fields = {
            "valid": "Valid",
            "disposable": "Disposable",
            "smtp_score": "SMTP Score",
            "overall_score": "Overall Score",
            "first_name": "First Name",
            "generic": "Generic",
            "common": "Common",
            "dns_valid": "DNS Valid",
            "honeypot": "Honeypot",
            "deliverability": "Deliverability",
            "frequent_complainer": "Frequent Complainer",
            "spam_trap_score": "Spam Trap Score",
            "catch_all": "Catch All",
            "timed_out": "Timed Out",
            "suspect": "Suspect",
            "recent_abuse": "Recent Abuse",
            "suggested_domain": "Suggested Domain",
            "leaked": "Leaked",
            "sanitized_email": "Sanitized Email",
            "domain_age": "Domain Age",
            "first_seen": "First Seen",
        }
        self.phone_enrich_fields = {
            "formatted": "Formatted",
            "local_format": "Local Format",
            "valid": "Valid",
            "recent_abuse": "Recent Abuse",
            "VOIP": "VOIP",
            "prepaid": "Prepaid",
            "risky": "Risky",
            "active": "Active",
            "carrier": "Carrier",
            "line_type": "Line Type",
            "city": "City",
            "zip_code": "Zip Code",
            "dialing_code": "Dialing Code",
            "active_status": "Active Status",
            "leaked": "Leaked",
            "name": "Name",
            "timezone": "Timezone",
            "do_not_call": "Do Not Call",
            "country": "Country",
            "region": "Region",
        }

    def _query(self, url: str, params: dict = None) -> Response:
        """General get method to fetch the response from IPQualityScore."""
        try:
            response = self.session.get(url, headers=self.headers, params=params).json()
            if str(response["success"]) != "True":
                msg = response["message"]
                self.helper.log_error(f"Error: {msg}")
                return None
            return response
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            msg = "Error connecting with the IPQualityScore."
            self.helper.log_error(f"{msg} Error: {error}")
            return None

    def get_ipqs_info(self, enrich_type, enrich_value):
        """
        Returns the IPQS data.
        """
        url = f"{self.url}/{enrich_type}"
        params = {enrich_type: enrich_value}
        try:
            response = self._query(url, params)
        except HTTPError as error:
            msg = f"Error when requesting data from IPQualityScore. {error.response}: {error.response.reason}"
            self.helper.log_error(msg)
            raise
        return response
