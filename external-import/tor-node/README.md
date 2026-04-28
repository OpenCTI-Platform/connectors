# Tor Exit-Node External Import Connector

This connector imports the current Tor exit node list from the official Tor Project bulk list.

## Implementation Notes
- Uses OpenCTI SDK patterns.
- STIX 2.1 compliant.
- Reads from `https://check.torproject.org/torbulkexitlist`.

## Usage
- Configure OpenCTI instance and run the connector via the OpenCTI UI or CLI.
