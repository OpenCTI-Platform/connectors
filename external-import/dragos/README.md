# WIP

## Aditional information

### Geocoding

Dragos models Geolocation with a specific Tag type. This Tag object only provide the name of the geolocation. To retrieve the Location Type for the OpenCTI platform and make the correct relationshhips, a geocoding service can be provided to the Connector.

#### OpenCTI platform as a Geocoding service

We provide an adapter to use the OpenCTI platform (itself) as a Geocoding service. This adapter searches the existing Locations using their Names and their Aliases in the OpenCTI platform.

If several candidates are found for a given name, the adapter will not choose between them.

Please note that the supported geolocation types with this adapter are only 'Country', 'City', 'Region' and 'Position'. The 'Administrative-Area' is not supported for the moment.
