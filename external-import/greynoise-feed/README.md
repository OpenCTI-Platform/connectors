# OpenCTI GreyNoise Feed

The connector uses the GreyNoise API to collect Internet Scanner IPs using a GreyNoise Feed.
You must have a GreyNoise subscription to use this feature.

## Installation

### Requirements

- OpenCTI Platform >= 5.9.6
- GreyNoise Subscription with Feed

### Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__)

### Debugging

Ensure that the GreyNoise API is reachable from the OpenCTI system. Check logs for details on where failures may occur and feel free to reach out to [support@greynoise.io](mailto:support@greynoise.io) for assistance

### Additional information

This feed will ingest a list of IPv4 indicators observed by GreyNoise and create an appropriate Indicator and Observable record. Additional vulnerability records will also be created when an associated tag is directly tied to that vulnerability.

Additional enrichment information can be retrieved using the GreyNoise enrichment integration in conjunction with this integration.
