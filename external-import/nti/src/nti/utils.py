def get_obs_value(helper, entity):
    """
    Used to obtain value from observables or indicators.
    :param entity: entire object
    :param helper: OpenCTI Connector Helper function
    :return: value of this object
    """
    if entity.get("observables"):
        observable = entity.get("observables")[0]
        if observable.get("address"):
            return observable.get("address").get("value")
        elif observable.get("type") == "file":
            return get_hash_name(observable.get("hashes"))
        else:
            return observable.get("value")
    elif entity.get("object", {}).get("type"):
        return entity.get("object", {}).get("value")
    else:
        helper.connector_logger.error(
            "[CONNECTOR] get_obs_value error...",
            entity,
        )
        return None


def get_hash_name(hashes: dict):
    """
    :param hashes: hashes from File
    :return: one hash used for naming a File
    """
    if not hashes:
        return None
    if hashes.get("MD5"):
        return hashes.get("MD5")
    elif hashes.get("SHA1"):
        return hashes.get("SHA1")
    elif hashes.get("SHA256"):
        return hashes.get("SHA256")
    elif hashes.get("SHA3-256"):
        return hashes.get("SHA3-256")
    else:
        return hashes
