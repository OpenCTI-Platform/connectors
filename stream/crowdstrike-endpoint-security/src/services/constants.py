# Map OCTI main observable type to Crowdstrike type
observable_type_mapper = {
    "domain-name:value": "domain",
    "hostname:value": "domain",
    "ipv4-addr:value": "ipv4",
    "ipv6-addr:value": "ipv6",
    "file:hashes.'SHA-256'": "sha256",
    "file:hashes.'MD5'": "md5"
}
