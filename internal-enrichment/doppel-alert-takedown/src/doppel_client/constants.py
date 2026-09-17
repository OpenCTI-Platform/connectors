# OpenCTI connector releases track the pinned pycti version. Bump this value
# whenever the connector is released against a new OpenCTI version.
DOPPEL_CLIENT_VERSION = "7.260901.0"
DOPPEL_ATTRIBUTION_HEADERS = {
    "x-doppel-client": f"opencti/{DOPPEL_CLIENT_VERSION}",
    "User-Agent": f"doppel-opencti/{DOPPEL_CLIENT_VERSION}",
}
