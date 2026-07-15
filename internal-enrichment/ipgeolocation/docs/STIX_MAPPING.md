# STIX 2.1 Object Mapping

## Overview

This document describes how IPGeolocation.io API response fields are mapped to
STIX 2.1 objects within the OpenCTI data model.

## Entity Mapping

| IPGeolocation.io Field    | STIX Type                | OpenCTI Type         | Notes                          |
|---------------------------|--------------------------|----------------------|--------------------------------|
| `location.country_name`   | `location`               | Country              | `x_opencti_location_type`      |
| `location.city`           | `location`               | City                 | Includes lat/lon               |
| `asn.as_number`           | `autonomous-system`      | Autonomous System    | Custom SCO in OpenCTI          |
| `asn.organization`        | `identity`               | Organization         | `identity_class=organization`  |
| `company.name`            | `identity`               | Organization         | Merged with ASN org            |
| `security.cloud_provider` | `identity`               | Organization         | Hosting/cloud provider         |
| `abuse.organization`      | `identity`               | Organization         | Abuse contact identity         |
| `hostname`                | `domain-name`            | Domain-Name          | SCO observable                 |
| Threat flags              | `indicator`              | Indicator            | STIX pattern, scored           |
| Enrichment summary        | `note`                   | Note                 | Markdown content               |
| Risk opinion              | `opinion`                | Opinion              | Mapped from risk level         |

## Relationship Mapping

| Source          | Relationship   | Target          | Condition                      |
|-----------------|----------------|-----------------|--------------------------------|
| IP Observable   | `located-at`   | Country         | Always (if country exists)     |
| City            | `located-at`   | Country         | Always (if city exists)        |
| IP Observable   | `belongs-to`   | ASN             | Always (if ASN exists)         |
| ASN             | `belongs-to`   | Organization    | Always (if org exists)         |
| IP Observable   | `related-to`   | Cloud Provider  | If `is_cloud_provider=true`    |
| IP Observable   | `related-to`   | Abuse Contact   | If abuse data exists           |
| IP Observable   | `resolves-to`  | Hostname        | If hostname exists             |
| Indicator       | `based-on`     | IP Observable   | If indicator created           |

## Label Mapping

| API Signal                | Label               | Condition               |
|---------------------------|----------------------|-------------------------|
| `is_vpn=true`            | `vpn`               | Security flag           |
| `is_proxy=true`          | `proxy`              | Security flag           |
| `is_residential_proxy`   | `residential-proxy`  | Security flag           |
| `is_tor=true`            | `tor`                | Security flag           |
| `is_relay=true`          | `relay`              | Security flag           |
| `is_bot=true`            | `bot`                | Security flag           |
| `is_spam=true`           | `spam`               | Security flag           |
| `is_known_attacker=true` | `known-attacker`     | Security flag           |
| `is_anonymous=true`      | `anonymous`          | Security flag           |
| `is_cloud_provider=true` | `cloud-provider`     | Security flag           |
| `company.type`           | e.g. `hosting`, `isp`| Infrastructure type     |
| `network.is_anycast`     | `anycast`            | Network flag            |
| Risk assessment           | `risk:low/med/high/critical` | Computed      |

## Score Mapping

| Source                     | OpenCTI Field          | Range  |
|----------------------------|------------------------|--------|
| Unified risk score         | `x_opencti_score`      | 0-100  |
| Risk confidence            | `confidence`           | 0-100  |

## Opinion Mapping

| Risk Level | STIX Opinion        |
|------------|---------------------|
| Low        | `strongly-disagree` |
| Medium     | `neutral`           |
| High       | `agree`             |
| Critical   | `strongly-agree`    |

Context: The opinion represents "This IP is malicious." Low risk = strongly
disagree with that statement; critical = strongly agree.
