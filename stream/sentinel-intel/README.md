# OpenCTI Sentinel Intel Connector

| Status | Date | Comment |
|--------|------|---------|
| Deprecated | 6.5 | Use Microsoft Sentinel Intel or Microsoft Graph Security Intel instead |

**WARNING: This connector is deprecated since version 6.5.**

Please migrate to:
- **Microsoft Sentinel Intel**: For Azure Sentinel integration (recommended)
- **Microsoft Graph Security Intel**: For legacy Microsoft Graph API integration

## Table of Contents

- [OpenCTI Sentinel Intel Connector](#opencti-sentinel-intel-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

This connector was designed to stream threat intelligence from OpenCTI to Microsoft Sentinel. It has been deprecated in favor of the newer Microsoft Sentinel Intel connector.

## Debugging

Not applicable - connector is deprecated.

## Additional information

**IMPORTANT: Migrate to the recommended connectors:**

- **For Azure Sentinel**: Use [Microsoft Sentinel Intel](https://github.com/OpenCTI-Platform/connectors/tree/master/stream/microsoft-sentinel-intel) (recommended)
- **For Legacy Graph API**: Use [Microsoft Graph Security Intel](https://github.com/OpenCTI-Platform/connectors/tree/master/stream/microsoft-graph-security-intel)

The Microsoft Sentinel Intel connector provides improved functionality and uses the modern Upload Indicators API.
