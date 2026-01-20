from .BaseHandler import BaseHandler

class IndicatorBundleHandler(BaseHandler):

    name = "Indicator Bundle"
    url_suffix = "/api/v2/ioc_bundles"
    response_key = "ioc_bundles"

    def map_bundle_reference(self, raw_bundle_ref: dict) -> dict:
        return {
            "id": raw_bundle_ref.get("id", ""),
            "created_at": raw_bundle_ref.get("created_at", 0),
            "stix_url": raw_bundle_ref.get("stix_url"),
        }


    def create_additional_objects(self, stix_content: list, bundle_ref: dict) -> list:
        # No additional objects are required
        return stix_content