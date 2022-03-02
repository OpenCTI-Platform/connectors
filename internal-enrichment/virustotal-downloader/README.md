# OpenCTI VirusTotal Downloader Connector

Virustotal Downloader Connector is an internal enrichment Connector that enables automated and manual submissions of file hashes (MD5, SHA1, and SHA256) to Virustotal to attempt to retreive associated file contents. If the file is found in Virustotal, a new Observable of type Artifact will be uploaded.
