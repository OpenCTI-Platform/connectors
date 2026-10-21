# v2.3.0

  + Add a Verity471 watcher **alerts** stream that ingests alerts from `/watchers/v1/alerts/stream` and maps them to STIX (each alert target wrapped in an `Incident`). Disabled by default; enable it with a non-zero `INTEL471_INTERVAL_ALERTS`. Restrict what is ingested with the optional `INTEL471_WATCHER_GROUP_IDS`, `INTEL471_WATCHER_IDS`, `INTEL471_STATUSES` and `INTEL471_IS_TRASHED_INCLUDED` filters. Because a Verity471 cursor is only valid for the filter set it was issued against, changing any of these filters discards the cursor and re-anchors the from-date to the last processed alert minus a small margin (a filter change re-ingests a small overlapping window; widening a filter backfills only the margin)
  + Upgrade `verity471[stix]` to version [1.2.1](https://github.com/intel471/verity471-python/releases/tag/v1.2.1) to pick up the alerts STIX mappings, a report inline-images fix, and quieter (non-error) handling of alert targets that no longer exist
  + Upgrade `pycti` to version [7.260921.0](https://pypi.org/project/pycti/7.260921.0/) to match the version pinned by `connectors-sdk`

# v2.2.2

  + Skip report types the account is not entitled to with a one-time warning instead of a recurring error traceback, and keep ingesting the other report types
  + Upgrade `verity471[stix]` to version [1.1.12](https://github.com/intel471/verity471-python/releases/tag/v1.1.12) to pick up the latest Verity471 API changes (optional/required field updates across Intel Reports, Data Leak Sites, Forums, Watchers and Messaging Services, and new default page sizes)
  + Accept `INTEL471_INITIAL_HISTORY_*` in epoch seconds as well as epoch milliseconds. A value given in seconds is detected and converted, instead of being read as a 1970 date and re-ingesting the whole history. An initial history already persisted in seconds in the connector state is repaired on the next run, and a value that is plausible as neither unit is now rejected on startup

# v2.2.1

  + Upgrade `verity471` to version [1.1.7](https://github.com/intel471/verity471-python/releases/tag/v1.1.7)
  + Add support for bulletproof hosting indicators

# v2.2.0

  + Added [Verity471](https://www.intel471.com/verity471) support with full feature and data parity alongside the existing Titan infrastructure.

# v2.1.4

  + Upgrade `Titan-Client` to version [1.20.0.15](https://github.com/intel471/titan-client-python/releases/tag/v1.20.0.15)
  + TLP markings on Relationship objects

# v2.1.3

  + Upgrade `Titan-Client` to version [1.20.0.13](https://github.com/intel471/titan-client-python/releases/tag/v1.20.0.13)
  + Make `rawText` in Reports optional
  + Map reliability in Information Reports (Inforeps)

# v2.1.2

  + Upgrade `Titan-Client` to version [1.20.0.12](https://github.com/intel471/titan-client-python/releases/tag/v1.20.0.12)
  + Improve handling of special characters in URLs
  + Make STIX IDs deterministic in TheatActor, Identity (organization) and in Relationships

# v2.1.1

  + Decrease page number in Reports stream for better performance 

# v2.1.0  

  + Add support for authenticated proxies (header-based proxy authentication)
  + Add inline images in Reports feed
  + Add description for threat actors derived from Actor Profile Reports
  + Add source characterisation for Info Reports
  + Add label `Intel 471 - sensitive source` for Reports derived from sensitive sources
  + Upgrade `Titan-Client` to version `1.20.0.9`

# v2.0.0  

  + Introduce new Reports feed in place of IoC feed
  + Add configuration item for Indicator decay score
  + Improve Vulnerabilities mapper
  + Map Intel 471 [General Intelligence Requirements (GIRs)](https://github.com/intel471/CU-GIR) into OpenCTI labels 
  + Upgrade `Titan-Client` to version `1.20.0.5`
