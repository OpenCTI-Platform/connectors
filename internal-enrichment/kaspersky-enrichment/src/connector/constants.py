SECTIONS = {
    "file_sections": {
        "mandatories_sections": ["LicenseInfo", "Zone", "FileGeneralInfo"],
        "supported_sections": [
            "LicenseInfo",
            "Zone",
            "FileGeneralInfo",
            "DetectionsInfo",
            "FileDownloadedFromUrls",
            "Industries",
            "FileNames",
        ],
    },
    "ipv4_sections": {
        "mandatories_sections": ["LicenseInfo", "Zone", "IpGeneralInfo"],
        "supported_sections": [
            "LicenseInfo",
            "Zone",
            "IpGeneralInfo",
            "FilesDownloadedFromIp",
            "HostedUrls",
            "IpWhoIs",
            "IpDnsResolutions",
            "Industries",
        ],
    },
    "domain_sections": {
        "mandatories_sections": ["LicenseInfo", "Zone", "DomainGeneralInfo"],
        "supported_sections": [
            "LicenseInfo",
            "Zone",
            "DomainGeneralInfo",
            "DomainDnsResolutions",
            "FilesDownloaded",
            "FilesAccessed",
            "Industries",
        ],
    },
    "url_sections": {
        "mandatories_sections": ["LicenseInfo", "Zone", "UrlGeneralInfo"],
        "supported_sections": [
            "LicenseInfo",
            "Zone",
            "UrlGeneralInfo",
            "FilesDownloaded",
            "FilesAccessed",
            "Industries",
        ],
    },
}

DATETIME_FORMAT = "%Y-%m-%dT%H:%MZ"
