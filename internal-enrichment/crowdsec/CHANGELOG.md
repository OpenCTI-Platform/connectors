# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## SemVer public API

The [public API](https://semver.org/spec/v2.0.0.html#spec-item-1)  for this project is defined by the set of 
functions provided by the `src` folder and the following files: `docker-compose.yml`, `Dockerfile`, `entrypoint.sh`

---

## [1.1.0](https://github.com/crowdsecurity/cs-opencti-internal-enrichment-connector/releases/tag/v1.1.0) - 2024-06-27
[_Compare with previous release_](https://github.com/crowdsecurity/cs-opencti-internal-enrichment-connector/compare/v1.0.0...v1.1.0)

### Changed

- Change default recommended name from `crowdsec` to `CrowdSec`
- Change CTI url to the console one
- Skip enrichment if the observable has already been enriched by CrowdSec less than a configurable time ago

### Added

- Add IPv6-Addr scope support
- Add setting to enable/disable the creation of an Indicator depending on the retrieved CrowdSec's CTI reputation
- Add setting to enable/disable the creation of an Attack Pattern from Mitre techniques
- Add setting to enable/disable the creation of a Vulnerability from CVE
- Add setting to enable/disable the creation of a Sighting related to CrowdSec organization
- Add setting to enable/disable the creation of a Sighting for each targeted country
- Add setting to enable/disable the creation of a Note in observable
- Add label types (`reputation`, `scenario's name`, `scenario's label`, `behavior`, `cve`, `mitre techniques` ) and associated colors
- And settings to enable/disable each label type
- Add setting to store last CrowdSec enrichment date in description
- Add setting to specify a minimum delay between two enrichments


### Removed

- Remove `CROWDSEC_NAME` and `CROWDSEC_DESCRIPTION` settings

---

## [1.0.0](https://github.com/crowdsecurity/cs-opencti-internal-enrichment-connector/releases/tag/v1.0.0) - 2024-04-19

- Initial release
