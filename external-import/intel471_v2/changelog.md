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
