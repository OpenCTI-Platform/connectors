def load_config_variables(helper, config):
    """
    Load required configuration values from config.yml.
    """

    return {
        "opencti_url": config["opencti"]["url"],
        "opencti_token": config["opencti"]["token"],
        "akamai_base_url": config["akamai"]["base_url"],
        "akamai_client_token": config["akamai"]["client_token"],
        "akamai_client_secret": config["akamai"]["client_secret"],
        "akamai_access_token": config["akamai"]["access_token"],
        "akamai_client_list_id": config["akamai"]["client_list_id"],
        "ssl_verify": config.get("ssl_verify", True), 
    }
