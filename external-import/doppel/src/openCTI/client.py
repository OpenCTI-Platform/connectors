import json


def send_to_opencti(stix_bundle, helper, update_existing):
    try:
        if isinstance(stix_bundle, dict):
            stix_bundle = json.dumps(stix_bundle)

        if not stix_bundle:
            helper.log_error("STIX bundle is empty or invalid.")
            return

        bundle_dict = json.loads(stix_bundle)
        helper.log_info(
            f"Sending STIX bundle with {len(bundle_dict.get('objects', []))} objects to OpenCTI."
        )
        helper.send_stix2_bundle(stix_bundle, update=update_existing)
        helper.log_info("STIX bundle sent successfully")

    except ValueError as e:
        helper.log_error(f"ValueError: {e} — Due to an empty or invalid STIX bundle.")
    except Exception as e:
        helper.log_error(f"Error sending STIX bundle: {str(e)}")
