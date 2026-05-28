# Map OCTI main observable type to Crowdstrike type
observable_type_mapper = {
    "domain-name:value": "domain",
    "hostname:value": "domain",
    "ipv4-addr:value": "ipv4",
    "ipv6-addr:value": "ipv6",
    "file:hashes.'SHA-256'": "sha256",
    "file:hashes.'MD5'": "md5",
}

# Map OpenCTI IOC score to Crowdstrike IOC severity
severity_mapper = {
    range(0, 20): "informational",
    range(20, 40): "low",
    range(40, 60): "medium",
    range(60, 80): "high",
    range(80, 101): "critical",
}

# Map OpenCTI IOC platforms to Crowdstrike platforms
platform_mapper = {
    "windows": "windows",
    "macos": "mac",
    "linux": "linux",
    "android": "android",
    "ios": "ios",
}
