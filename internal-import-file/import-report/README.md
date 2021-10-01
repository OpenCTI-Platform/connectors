# OpenCTI Report Import Connector

This connector allows organizations to feed information from report to OpenCTI.

This connector extracts the information in the report files and then matches it against regular expressions for Entities from the OpenCTI knowledge base or new Observables.

## General overview

OpenCTI data is coming from *import* connectors.

## Installation

### Requirements

- OpenCTI Platform >= 4.5.1

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `INTERNAL_IMPORT_FILE` (this is the connector type).                                                                                               |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | Option `ImportReport`                                                                                                                          |
| `connector_auto`                     | `CONNCETOR_AUTO`                    | Yes          | `false` Enable/disable auto import of report file                                                                                                          |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported file types: `'application/pdf','text/plain','text/html'`                                                                                                     |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `import_report_create_indicator`     | `IMPORT_REPORT_CREATE_INDICATOR`    | Yes          | Create an indicator for each extracted observable                                                                                                         |

After adding the connector, you should be able to extract information from a report.

### Debugging ###

In case the connector doesn't behave like it should, please change the `CONNECTOR_LOG_LEVEL` to `debug`.
This way you will get a log entry for every parsing step to verify each step.
Example

```
INFO:root:Parsing report TTest.pdf application/pdf
DEBUG:root:Observable match: 1322
DEBUG:root:Observable match: T1011.001
DEBUG:root:Observable match: T1012
DEBUG:root:Text: 'This group used T1011.001 and then continued on to further exploit the text which does not meet T1012, but everything went over the malicious AS 1322 since it covers many IPs.' -> extracts {1322: {'type': 'observable', 'category': 'Autonomous-System.number', 'match': 1322, 'range': (145, 149)}, 'T1011.001': {'type': 'observable', 'category': 'Attack-Pattern.x_mitre_id', 'match': 'T1011.001', 'range': (16, 25)}, 'T1012': {'type': 'observable', 'category': 'Attack-Pattern.x_mitre_id', 'match': 'T1012', 'range': (96, 101)}} 
DEBUG:root:Observable match: arp.exe
DEBUG:root:Observable match: cmd.exe
DEBUG:root:Entity match: 'cmd.exe' of regex: '[re.compile('\\bcmd.exe\\b', re.IGNORECASE), re.compile('\\bcmd\\b', re.IGNORECASE)]'
DEBUG:root:Entity match: 'cmd' of regex: '[re.compile('\\bcmd.exe\\b', re.IGNORECASE), re.compile('\\bcmd\\b', re.IGNORECASE)]'
DEBUG:root:Value cmd.exe is also matched by entity tool
DEBUG:root:Entity match: 'arp.exe' of regex: '[re.compile('\\barp.exe\\b', re.IGNORECASE), re.compile('\\bArp\\b', re.IGNORECASE)]'
DEBUG:root:Entity match: 'arp' of regex: '[re.compile('\\barp.exe\\b', re.IGNORECASE), re.compile('\\bArp\\b', re.IGNORECASE)]'
DEBUG:root:Value arp.exe is also matched by entity tool
DEBUG:root:Text: 'executed with arp.exe and cmd.exe to run it' -> extracts {'cmd': {'type': 'entity', 'category': 'tool', 'match': 'tool--01ad605b-5512-5046-997b-157c9f3ac378', 'range': (0, 0)}, 'arp': {'type': 'entity', 'category': 'tool', 'match': 'tool--14c7dce1-ff3b-5ed2-ab82-784e09c62bb1', 'range': (0, 0)}}
[...]
```

### Supported formats

*Please open a feature requests in case the current implemention doesn't fit your needs*

**File input format**
- PDF file
- Text file

**Extractable Entities/Stix Domain Objects**

| Extractable Entity | Based on | Example | Stix entity type and field | Note |
|-------------|-------------------------|------------------|------|----|
| Attack Pattern | MITRE ATT&CK Technique | T1234.001| AttackPattern.x_mitre_id |  |
| Country      | Based on registered entries in OpenCTI |France |Location.name, Location.aliases|  |
| Campaign |Based on registered entries in OpenCTI | Solarwinds Campaign | Campaign.name, Campaign.aliases|  |
| Course of Action | :x: | |
| Incident |Based on registered entries in OpenCTI | | Incident.name, Incident.aliases|  |
| Intrusion Set | Based on registered entries in OpenCTI | APT29| IntrusionSet.name, IntrusionSet.aliases| |
| Malware          | Based on registered entries in OpenCTI |BadPatch| Malware.name, Malware.aliases|  |
| Organization      | Based on registered entries in OpenCTI |Microsoft |Identity.name, Identity.aliases|  |
| Threat Actor | Based on registered entries in OpenCTI |  GRU| IntrusionSet.name, IntrusionSet.aliases| |
| Tool          | Based on registered entries in OpenCTI |cmd.exe |Tool.name, Tool.aliases| The Linux tool `at` is excluded due to too many false positives |
| Vulnerability | CVE Numbers             | CVE-2020-0688 | Vulnerability.name |  |
  
**Extractable Observables/Stix Cyber Observables**

| Extractable Observable/SCO | Stix Reference fields | Supported | Note |
|-----------------------------|------------------|------|---|
| Artifact | - | :x: | |
| AutonomousSystem        | AutonomousSystem.number| :heavy_check_mark: | | 
| Directory | - | :x: | |
| Domain Name | DomainName.value| :heavy_check_mark: | |
| EMail Address | EMail-Addr.value | :heavy_check_mark: ||
| EMail Message | - | :x: | |
| File | File.name, File.hashes (MD5, SHA-1, SHA-256) | :heavy_plus_sign: | |
| IPv4 Address | IPv4-Addr.value| :heavy_check_mark: ||  
| IPv6 Address | IPv6-Addr.value| :heavy_check_mark: ||
| MAC Address | Mac-Addr.value| :heavy_check_mark: | |
| Mutex | - |:x: | |
| Network Traffic | - | :x: | |
| Process | - | :x: | |
| Software | - | :x: | |
| URL | Url.value | :heavy_check_mark: | |
| User Account | - | :x: | |
| Windows Registry Key | WindowsRegistryKey.key | :heavy_plus_sign: | |
| X.509 Certificate | - | :x: | |

:heavy_check_mark: = Fully implemented

:heavy_plus_sign: = Not entirely implemented

:x: = Not implemented

*Reference: https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html*

### Configuration (reportimporter/config/)

**observable_config.ini**

```
# report-import supports 2 SCO extraction methods. 'regex' and 'library' (uses ioc_finder library)
detection_option = regex/library

# if 'regex', define regex patterns
regex_patterns =
  \bpattern1\b
  \bpattern2\b
  
# if 'library', then define iocfinder function
iocfinder_function = parse_urls


# define Stix target where the result will be stored
stix_target = Url.value

# (optional) If certain values should be excluded, define either a list of files from the 'filter_list' directory 
filter_config =
    filter_list_Domain
```

**entity_config.ini**
```
# Stix class is the name of the corresponding OpenCTI API class which will be executed
# The requests are called `self.api.<stix_class>.list()
stix_class = location

# (optional) filter the output of the list requests using the filter values
filter = {"key": "entity_type", "values": ["Country"]}

# Use only the values of the defined fields/attributes for the report parsing 
fields =
    name
    aliases
    
# (optional) If a location is found in a text, which is also categorized as ie. the SCO Domain-Name, then
# ignore this entity match. This can be usefull, to prevent entity matches from unreliable information sources.
# Example: login.microspoft.phsishingstite.com should not match the Organization Microsoft 
omit_match_in =
    Domain-Name.value
```

[1] https://github.com/OpenCTI-Platform/client-python/tree/master/pycti/entities