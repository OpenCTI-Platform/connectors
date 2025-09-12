# OpenCTI VirusTotal Downloader Connector

## Status Filigran

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified | -    | -       |

## Introduction
Virustotal Downloader Connector is an internal enrichment Connector that enables automated and manual submissions of file hashes (MD5, SHA1, and SHA256) to Virustotal to attempt to retreive associated file contents. If the file is found in Virustotal, a new Observable of type Artifact will be uploaded.

## Configuration variables environment

Find all the configuration variables available (default/required) here: [Connector Configurations](./__metadata__)