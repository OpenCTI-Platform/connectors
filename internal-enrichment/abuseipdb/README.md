# OpenCTI Internal Enrichment Connector AbuseIPDB

## Status Filigran

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified | -    | -       |

## Introduction

**Introducing AbuseIPDB**

AbuseIPDB is a robust platform that collects and shares data on malicious IP addresses reported by users around the world. It serves as a valuable tool for cybersecurity teams looking to identify and block IP addresses associated with abusive activities, such as spam, hacking attempts, and other malicious acts. By providing a community-driven database, AbuseIPDB helps organizations strengthen their defenses against network-based threats.

The integration of AbuseIPDB with OpenCTI allows for the seamless importation of malicious IP address data into the threat intelligence platform. This integration enriches threat intelligence by providing real-time context on potentially harmful IPs, enabling security teams to implement more effective blocking and monitoring strategies. By utilizing this data, organizations can enhance their ability to preemptively identify and mitigate threats from malicious IP sources.

## Requirements

- python-dateutil==2.9.0.post0
- pydantic-settings==2.10.1
- pycti==6.7.15

## Configuration variables environment

Find all the configuration variables available (default/required) here: [Connector Configurations](./__metadata__)