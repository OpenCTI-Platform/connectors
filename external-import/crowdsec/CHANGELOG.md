# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## SemVer public API

The [public API](https://semver.org/spec/v2.0.0.html#spec-item-1)  for this project is defined by the set of 
functions provided by the `src` folder and the following files: `docker-compose.yml`, `Dockerfile`, `entrypoint.sh`

---


## [1.0.0](https://github.com/crowdsecurity/cs-opencti-external-import-connector/releases/tag/v1.0.0) - 2025-07-11
[_Compare with previous release_](https://github.com/crowdsecurity/cs-opencti-external-import-connector/compare/v0.0.1...v1.0.0)

### Changed

- Use `smoke/search` CTI endpoint instead of dumps to retrieve IPs
- Set default value of `CROWDSEC_ENRICHMENT_THRESHOLD_PER_IMPORT` to 2000

---

## [0.0.1](https://github.com/crowdsecurity/cs-opencti-external-import-connector/releases/tag/v0.0.1) - 2024-06-27

- Initial release
