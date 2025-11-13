# VirusTotal Connector

* This connector checks files, IP addresses, domains, and URLs against the VirusTotal API for enrichment.
* It requires a VirusTotal API Key.

* The following outputs are enabled by default, and are configurable:
  * Full findings are reported as a table in a new note that is attached to the entity being enriched
  * The score of the indicator will be adjusted to the count of VT engines that find the entity to be a positive
  * If an observable has a count of positive findings over 10, a corresponding indicator will be created.
  * For the corresponding indicator, the **Detection** flag will be set to TRUE
  * If a sample of the artifact is available and not yet in OpenCTI, it will be imported (if under 32MB)

  

## Installation

### Requirements

- OpenCTI Platform >= 6.0.6

## Configuration variables environment

Find all the configuration variables available (default/required) here: [Connector Configurations](./__metadata__)

---

### Debugging

Set the appropriate log level for debugging. Use `self.helper.log_{LOG_LEVEL}("Message")` for logging, e.g., `self.helper.log_error("Error message")`.

### Additional Information

The VirusTotal connector performs enrichment for files, IP addresses, domains, and URLs. It sends observables to the VirusTotal API and creates indicators in OpenCTI based on threat intelligence from VirusTotal.
Information when creating a note full report ‘Last Analysis Results’ any value returned by virustotal that is falsy will return ‘N/A’.
