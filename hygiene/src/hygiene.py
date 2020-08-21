import os
import yaml

from pymispwarninglists import WarningLists
from pycti import OpenCTIConnectorHelper

# At the moment it is not possible to map lists to their upstream path.
# Thus we need to have our own mapping here.
# Reference: https://github.com/MISP/misp-warninglists/issues/142
LIST_MAPPING = {
    "List of known gmail sending IP ranges": "/lists/google-gmail-sending-ips/list.json",
    "List of known domains to know external IP": "/lists/whats-my-ip/list.json",
    "Top 500 domains and pages from https://moz.com/top500": "/lists/moz-top500/list.json",
    "List of known Windows 10 connection endpoints": "/lists/microsoft-win10-connection-endpoints/list.json",
    "List of known security providers/vendors blog domain": "/lists/security-provider-blogpost/list.json",
    "List of known hashes with common false-positives (based on Florian Roth input list)": "/lists/common-ioc-false-positive/list.json",
    "Specialized list of IPv4 addresses belonging to common VPN providers and datacenters": "/lists/vpn-ipv4/list.json",
    "List of known Office 365 IP address ranges in China": "/lists/microsoft-office365-cn/list.json",
    "List of RFC 5735 CIDR blocks": "/lists/rfc5735/list.json",
    "List of RFC 5771 multicast CIDR blocks": "/lists/multicast/list.json",
    "CRL Warninglist": "/lists/crl-ip-hostname/list.json",
    "List of RFC 1918 CIDR blocks": "/lists/rfc1918/list.json",
    "Top 1000 website from Alexa": "/lists/alexa/list.json",
    "List of known Office 365 URLs address ranges": "/lists/microsoft-office365/list.json",
    "List of known bank domains": "/lists/bank-website/list.json",
    "List of known IPv6 public DNS resolvers": "/lists/public-dns-v6/list.json",
    "List of known google domains": "/lists/google/list.json",
    "List of known microsoft domains": "/lists/microsoft/list.json",
    "List of known Ovh Cluster IP": "/lists/ovh-cluster/list.json",
    "List of known domains used by automated malware analysis services & security vendors": "/lists/automated-malware-analysis/list.json",
    "List of known Cloudflare IP ranges": "/lists/cloudflare/list.json",
    "List of known hashes for empty files": "/lists/empty-hashes/list.json",
    "Common contact e-mail addresses": "/lists/common-contact-emails/list.json",
    "Fingerprint of trusted CA certificates": "/lists/mozilla-CA/list.json",
    "Covid-19 Cyber Threat Coalition's Whitelist": "/lists/covid-19-cyber-threat-coalition-whitelist/list.json",
    "List of known Akamai IP ranges": "/lists/akamai/list.json",
    "Specialized list of IPv6 addresses belonging to common VPN providers and datacenters": "/lists/vpn-ipv6/list.json",
    "List of known Microsoft Azure Datacenter IP Ranges": "/lists/microsoft-azure/list.json",
    "List of IPv6 link local blocks": "/lists/ipv6-linklocal/list.json",
    "List of known public DNS resolvers expressed as hostname": "/lists/public-dns-hostname/list.json",
    "Top 1000 website from Cisco Umbrella": "/lists/cisco_top1000/list.json",
    "List of hashes for EICAR test virus": "/lists/eicar.com/list.json",
    "University domains": "/lists/university_domains/list.json",
    "List of known Office 365 IP address ranges": "/lists/microsoft-office365-ip/list.json",
    "List of known Amazon AWS IP address ranges": "/lists/amazon-aws/list.json",
    "List of known Googlebot IP ranges": "/lists/googlebot/list.json",
    "TLDs as known by IANA": "/lists/tlds/list.json",
    "List of RFC 3849 CIDR blocks": "/lists/rfc3849/list.json",
    "List of known Office 365 Attack Simulator used for phishing awareness campaigns": "/lists/microsoft-attack-simulator/list.json",
    "List of RFC 6761 Special-Use Domain Names": "/lists/rfc6761/list.json",
    "List of RFC 6598 CIDR blocks": "/lists/rfc6598/list.json",
    "List of known IPv4 public DNS resolvers": "/lists/public-dns-v4/list.json",
    "List of known dax30 webpages": "/lists/dax30/list.json",
    "List of disposable email domains": "/lists/disposable-email/list.json",
    "Top 1,000,000 most-used sites from Tranco": "/lists/tranco/list.json",
    "Valid covid-19 related domains": "/lists/covid/list.json",
    "Top 10K websites from Majestic Million": "/lists/majestic_million/list.json",
    "List of known URL Shorteners domains": "/lists/url-shortener/list.json",
    "Covid-19 Krassi's Whitelist": "/lists/covid-19-krassi-whitelist/list.json",
    "List of known Wikimedia address ranges": "/lists/wikimedia/list.json",
    "List of known sinkholes": "/lists/sinkholes/list.json",
    "Second level TLDs as known by Mozilla Foundation": "/lists/second-level-tlds/list.json",
    "Fingerprint of known intermedicate of trusted certificates": "/lists/mozilla-IntermediateCA/list.json",
}


class HygieneConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.warninglists = WarningLists()

        # Create Hygiene Tag
        self.label_hygiene = self.helper.api.label.create(
            value="Hygiene", color="#fc0341"
        )

    def _process_observable(self, observable) -> list:
        # Extract IPv4, IPv6 and Domain from entity data
        observable_value = observable["observable_value"]

        # Search in warninglist
        result = self.warninglists.search(observable_value)

        # Iterate over the hits
        if result:
            self.helper.log_info(
                "Hit found for %s in warninglists" % (observable_value)
            )

            for hit in result:
                self.helper.log_info(
                    "Type: %s | Name: %s | Version: %s | Descr: %s"
                    % (hit.type, hit.name, hit.version, hit.description)
                )

                # We set the score based on the number of warning list entries
                if len(result) >= 5:
                    score = "5"
                elif len(result) >= 3:
                    score = "10"
                elif len(result) == 1:
                    score = "15"
                else:
                    score = "20"

                self.helper.log_info(
                    f"number of hits ({len(result)}) setting score to {score}"
                )

                self.helper.api.stix_cyber_observable.add_label(
                    id=observable["id"], label_id=self.label_hygiene["id"]
                )

                for indicator_id in observable["indicatorsIds"]:
                    self.helper.api.stix_domain_object.add_label(
                        id=indicator_id, label_id=self.label_hygiene["id"]
                    )
                    self.helper.api.stix_domain_object.update_field(
                        id=indicator_id, key="x_opencti_score", value=score
                    )

                # Create external references
                external_reference_id = self.helper.api.external_reference.create(
                    source_name="misp-warninglist",
                    url="https://github.com/MISP/misp-warninglists/tree/master"
                    + LIST_MAPPING[hit.name],
                    external_id=hit.name,
                    description=hit.description,
                )
                self.helper.api.stix_cyber_observable.add_external_reference(
                    id=observable["id"],
                    external_reference_id=external_reference_id["id"],
                )

            return ["observable value found on warninglist and tagged accordingly"]

    def _process_message(self, data) -> list:
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_observable.read(id=entity_id)
        return self._process_observable(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    HygieneInstance = HygieneConnector()
    HygieneInstance.start()
