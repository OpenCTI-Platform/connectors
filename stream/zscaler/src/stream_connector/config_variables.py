from pycti import get_config_variable


def load_config_variables(helper, config):
    # OpenCTI Variables
    opencti_url = get_config_variable("OPENCTI_URL", ["opencti", "url"], config)
    opencti_token = get_config_variable("OPENCTI_TOKEN", ["opencti", "token"], config)
    ssl_verify = get_config_variable(
        "OPENCTI_SSL_VERIFY", ["opencti", "ssl_verify"], config, default=False
    )

    # Connector variables
    connector_name = get_config_variable(
        "CONNECTOR_NAME", ["connector", "name"], config
    )
    connector_id = get_config_variable("CONNECTOR_ID", ["connector", "id"], config)
    connector_type = get_config_variable(
        "CONNECTOR_TYPE", ["connector", "type"], config
    )
    connector_scope = get_config_variable(
        "CONNECTOR_SCOPE", ["connector", "scope"], config
    )
    connector_log_level = get_config_variable(
        "CONNECTOR_LOG_LEVEL", ["connector", "log_level"], config, default="info"
    )
    connector_live_stream_id = get_config_variable(
        "CONNECTOR_LIVE_STREAM_ID", ["connector", "live_stream_id"], config
    )
    connector_live_stream_listen_delete = get_config_variable(
        "CONNECTOR_LIVE_STREAM_LISTEN_DELETE",
        ["connector", "live_stream_listen_delete"],
        config,
        default=True,
    )
    connector_live_stream_no_dependencies = get_config_variable(
        "CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES",
        ["connector", "live_stream_no_dependencies"],
        config,
        default=True,
    )

    # Zscaler Variables
    zscaler_username = get_config_variable(
        "ZSCALER_USERNAME", ["zscaler", "username"], config
    )
    zscaler_password = get_config_variable(
        "ZSCALER_PASSWORD", ["zscaler", "password"], config
    )
    zscaler_api_key = get_config_variable(
        "ZSCALER_API_KEY", ["zscaler", "api_key"], config
    )
    zscaler_blacklist_name = get_config_variable(
        "ZSCALER_BLACKLIST_NAME",
        ["zscaler", "blacklist_name"],
        config,
        default="BLACK_LIST_DYNDNS",
    )

    return {
        "opencti_url": opencti_url,
        "opencti_token": opencti_token,
        "ssl_verify": ssl_verify,
        "connector_name": connector_name,
        "connector_id": connector_id,
        "connector_type": connector_type,
        "connector_scope": connector_scope,
        "connector_log_level": connector_log_level,
        "connector_live_stream_id": connector_live_stream_id,
        "connector_live_stream_listen_delete": connector_live_stream_listen_delete,
        "connector_live_stream_no_dependencies": connector_live_stream_no_dependencies,
        "zscaler_username": zscaler_username,
        "zscaler_password": zscaler_password,
        "zscaler_api_key": zscaler_api_key,
        "zscaler_blacklist_name": zscaler_blacklist_name,  #  Parameter for the blacklist name
    }
