# v1.1.3

- Upgraded `Titan-Client` to version `1.20.0.1`. It provides following changes to STIX mappers:
  + Adding `x_opencti_main_observable_type` property to Observables
  + Adding author to Observables
  + Adding relationships between Observable and Indicator to related reports, so they are mapped correctly in Knowledge tab
- Fixed paging on IoCs

# v1.1.2  

- Upgraded `Titan-Client` to version `1.19.7.3` to properly handle CVE reports without GiRs.

# v1.1.1  

- Upgraded `Titan-Client` to version `1.19.7.2` to fix PyYAML dependency.

# v1.1.0  
  
- Upgraded `Titan-Client` to version `1.19.7`. It provides following changes to STIX mappers:
  + IP address and File types from IOC feed are now mapped
  + Added confidence mapping in reports
  + Added report type mapping
  + Tagging reports with malware family if available
  + Added full report content as an attachment
- Added support for Proxy server when calling Titan API

# v1.0.3  
  
- Upgraded `Titan-Client` to version `1.19.3.1`, which supports caching.  

# v1.0.2

- Fixed `api_key` variable pulled from config file
